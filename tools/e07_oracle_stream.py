#!/usr/bin/env python3
"""E07 Oracle-carried opaque TLS byte-stream endpoint.

Trusted caller/orchestrator invokes snapshot/deliver via its existing Oracle
terminal RPC on *each* node. This script has no Oracle account or access
decision; it does not reach the Internet or select an A05 program.
The carrier is loopback-only and retains byte order across interrupted polls.
It cannot execute unattended without an external Oracle tool invoker.
"""
import argparse
from contextlib import contextmanager
import base64
import binascii
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import stat
import sys
import threading
import time

# Load the Windows-only native ACL validator from this script's own directory,
# both for direct CLI execution and importlib-loaded contract tests.
if os.name == "nt":
    import importlib.util
    _win_spec = importlib.util.spec_from_file_location(
        "_ptah_e07_windows_custody", Path(__file__).with_name("e07_windows_custody.py"))
    _win_module = importlib.util.module_from_spec(_win_spec)
    _win_spec.loader.exec_module(_win_module)
    windows_private_acl = _win_module.validate_private_windows
    windows_claim_new_owner = _win_module.claim_new_windows_owner

MAX_CHUNK = 32768
MAX_ENCODED_CHUNK = 4 * ((MAX_CHUNK + 2) // 3)
MAX_BATCH = 32
MAX_TOTAL = 8 * 1024 * 1024
MAX_RUNTIME = 300

def is_path_alias(path):
    """Reject symlinks and Windows junction/reparse aliases before path I/O."""
    try:
        identity = Path(path).lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISLNK(identity.st_mode) or
            bool(getattr(identity, "st_file_attributes", 0) &
                 getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))


def require_private_custody(path, identity, label):
    if os.name == "nt":
        # POSIX mode/st_uid are not Windows NTFS authorization evidence.
        windows_private_acl(path)
    else:
        if identity.st_uid != os.geteuid():
            raise ValueError("private carrier " + label + " owner required")
        if stat.S_IMODE(identity.st_mode) & 0o077:
            raise ValueError("private carrier " + label + " required")


def exclusive_open_flags(access):
    # O_EXCL|O_CREAT rejects existing links on Windows as well as POSIX.
    # O_NOFOLLOW adds a second guard where the platform provides it.
    return access | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


def require_unaliased_state_path(state):
    # Preserve lexical path identity: resolving first would hide symlink parents.
    root = Path(state)
    if not root.is_absolute():
        raise ValueError("absolute carrier state path required")
    if ".." in root.parts:
        raise ValueError("carrier state parent traversal prohibited")
    if os.name == "nt" and root.drive.startswith("\\\\"):
        raise ValueError("local carrier state path required")
    if any(is_path_alias(parent) for parent in root.parents):
        raise ValueError("symlinked carrier state ancestor prohibited")
    return root

_DB_OPEN_LOCK = threading.RLock()
_ADMISSION_LOCK_NAME = "carrier.admission.lock"

@contextmanager
def carrier_admission_lock(state, preparing=False):
    """Serialize SQLite sidecar admission and lifetime across cooperating processes.

    The lock is exclusively created during prepare; no operation repairs a
    missing or foreign-owned lock. This is not a defense against an attacker
    concurrently replacing filesystem path components.
    """
    root = require_unaliased_state_path(state)
    if not root.is_dir() or is_path_alias(root):
        raise ValueError("existing real state directory required")
    root_identity = root.lstat()
    require_private_custody(root, root_identity, "state directory")
    path = root / _ADMISSION_LOCK_NAME
    if not preparing and not (root / "carrier.sqlite3").exists():
        raise ValueError("prepared carrier database required")
    try:
        identity = path.lstat()
    except FileNotFoundError:
        raise ValueError("prepared carrier admission lock required") from None
    if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1 or is_path_alias(path):
        raise ValueError("real unaliased carrier admission lock required")
    require_private_custody(path, identity, "admission lock")
    # The path can be swapped for a FIFO after lstat. Nonblocking open
    # prevents an untrusted FIFO with no writer from hanging the Oracle RPC;
    # fstat below still rejects the substituted non-regular inode.
    try:
        fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        # Only missing/substituted lock paths are identity races. Preserve
        # unrelated I/O, descriptor exhaustion and permission diagnostics.
        if error.errno not in (errno.ENOENT, errno.ENOTDIR,
                               getattr(errno, "ELOOP", None)):
            raise
        raise ValueError("carrier admission lock identity changed") from error
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (identity.st_dev, identity.st_ino)):
            raise ValueError("carrier admission lock identity changed")
        require_private_custody(path, opened, "admission lock")
        # Bound contention rather than hanging an Oracle RPC indefinitely.
        deadline = time.monotonic() + 7
        if os.name == "nt":
            import msvcrt
        else:
            import fcntl
        while True:
            try:
                if os.name == "nt":
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as error:
                # Only a contended nonblocking lock is retryable. EIO, EBADF,
                # EINVAL and other failures must retain their original errno
                # rather than being mislabeled as a seven-second lock timeout.
                if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError("carrier admission lock busy") from error
                time.sleep(0.02)
        try:
            # Holding the original lock inode does not protect a newly named
            # state directory. Recheck the directory identity after flock,
            # before opening SQLite by pathname. This detects observed root
            # replacement; it is not race-free dirfd-relative custody.
            try:
                current_root = root.lstat()
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ENOTDIR,
                                       getattr(errno, "ELOOP", None)):
                    raise
                raise ValueError("carrier state directory identity changed") from error
            if (not stat.S_ISDIR(current_root.st_mode) or is_path_alias(root)
                    or (current_root.st_dev, current_root.st_ino,
                        current_root.st_mode, current_root.st_uid,
                        current_root.st_gid, current_root.st_nlink)
                    != (root_identity.st_dev, root_identity.st_ino,
                        root_identity.st_mode, root_identity.st_uid,
                        root_identity.st_gid, root_identity.st_nlink)):
                raise ValueError("carrier state directory identity changed")
            require_private_custody(root, current_root, "state directory")
            try:
                current = path.lstat()
            except OSError as error:
                # A missing or displaced lock pathname fails closed, but an
                # unrelated filesystem error keeps its original diagnosis.
                if error.errno not in (errno.ENOENT, errno.ENOTDIR,
                                       getattr(errno, "ELOOP", None)):
                    raise
                raise ValueError("carrier admission lock identity changed") from error
            # A new hardlink can alias the lock after its initial lstat/fstat.
            # Check the pathname and locked descriptor again before SQLite.
            locked = os.fstat(fd)
            if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                    or locked.st_nlink != 1
                    or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
                    or (locked.st_dev, locked.st_ino) != (opened.st_dev, opened.st_ino)):
                raise ValueError("carrier admission lock identity changed")
            require_private_custody(path, current, "admission lock")
            yield
        finally:
            if os.name == "nt":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

def dbconnect(state, create=False):
    # A second carrier pump thread must not inspect a newly created Windows
    # SQLite WAL/SHM file before the creator has assigned TokenUser ownership.
    # This serializes admission/open in this process; it is NOT cross-process
    # or race-free filesystem authority.
    with _DB_OPEN_LOCK:
        return _dbconnect_locked(state, create)

def _dbconnect_locked(state, create=False):
    root = require_unaliased_state_path(state)
    if not root.is_dir() or is_path_alias(root):
        raise ValueError("existing real state directory required")
    root_identity = root.stat()
    require_private_custody(root, root_identity, "state directory")
    db_path = root / "carrier.sqlite3"
    if create:
        # Only prepare may create a database, and never over an existing alias.
        fd = os.open(db_path, exclusive_open_flags(os.O_RDWR), 0o600)
        os.close(fd)
        if os.name == "nt":
            windows_claim_new_owner(db_path)
    try:
        identity = db_path.lstat()
    except FileNotFoundError:
        raise ValueError("prepared carrier database required") from None
    if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1 or is_path_alias(db_path):
        raise ValueError("real unaliased carrier database required")
    require_private_custody(db_path, identity, "database")
    # SQLite may open these companion files implicitly. Reject pre-existing
    # aliases before giving SQLite the path; this is not a race-free dirfd
    # custody proof and does not replace independent E07 qualification.
    missing_sidecars = []
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = db_path.with_name(db_path.name + suffix)
        try:
            sidecar_identity = sidecar.lstat()
        except FileNotFoundError:
            missing_sidecars.append(sidecar)
            continue
        if (not stat.S_ISREG(sidecar_identity.st_mode) or sidecar_identity.st_nlink != 1
                or is_path_alias(sidecar)):
            raise ValueError("real unaliased carrier sidecar required")
        require_private_custody(sidecar, sidecar_identity, "sidecar")
    conn = sqlite3.connect(str(db_path), timeout=7)
    try:
        # Schema/PRAGMA/commit failures must close the handle before the
        # caller releases the cross-process admission lock. A leaked handle
        # can retain Windows SQLite WAL/SHM custody beyond this operation.
        # SQLite may return a different journal mode when the backing
        # filesystem cannot provide WAL. The carrier's concurrent reader/
        # writer and sidecar custody contract must never silently downgrade.
        journal_mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
        if (not journal_mode or type(journal_mode[0]) is not str
                or journal_mode[0].lower() != "wal"):
            raise ValueError("carrier WAL journal mode required")
        conn.execute("PRAGMA busy_timeout=7000")
        conn.execute("CREATE TABLE IF NOT EXISTS outbound(seq INTEGER PRIMARY KEY, content BLOB NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS inbound(seq INTEGER PRIMARY KEY, content BLOB NOT NULL)")
        conn.commit()
        if os.name == "nt":
            # SQLite may create WAL/SHM files after the pre-open check.
            # Only freshly created sidecars may be assigned TokenUser;
            # existing foreign-owned sidecars must remain rejected.
            for sidecar in missing_sidecars:
                if not os.path.lexists(sidecar):
                    continue
                identity = sidecar.lstat()
                if (not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1
                        or is_path_alias(sidecar)):
                    raise ValueError("real unaliased carrier sidecar required")
                windows_claim_new_owner(sidecar)
                require_private_custody(sidecar, sidecar.lstat(), "sidecar")
    except Exception:
        conn.close()
        raise
    return conn

@contextmanager
def dbtransaction(state):
    """Commit or roll back each operation and always release its SQLite handle."""
    # Keep the lock through transaction completion and close: WAL/SHM files
    # can be created or removed after the initial SQLite connection opens.
    with _DB_OPEN_LOCK:
        with carrier_admission_lock(state):
            conn = dbconnect(state)
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

def prepare(state):
    p = require_unaliased_state_path(state)
    if p.exists():
        raise ValueError("state must be newly created; cannot reuse production paths")
    p.mkdir(parents=True, mode=0o700)
    if os.name == "nt":
        windows_claim_new_owner(p)
    lock_path = p / _ADMISSION_LOCK_NAME
    fd = os.open(lock_path, exclusive_open_flags(os.O_RDWR), 0o600)
    try:
        os.write(fd, b"\0")
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == "nt":
        windows_claim_new_owner(lock_path)
    with _DB_OPEN_LOCK:
        with carrier_admission_lock(p, preparing=True):
            conn = dbconnect(p, create=True)
            conn.close()
    print(json.dumps({"state":str(p),"new":True,"listener":"loopback_only"}))

def require_carrier_stream_table(table):
    # Table identifiers cannot be SQL parameters; keep this internal helper
    # limited to the two durable opaque-byte journals it actually owns.
    if type(table) is not str or table not in ("outbound", "inbound"):
        raise ValueError("invalid carrier stream table")


def require_healthy_carrier_history(conn, table):
    """Reject a damaged durable prefix before any resumed TLS read.

    Checking only the acknowledged cursor and next batch can conceal an
    earlier missing sequence or invalid BLOB. The bounded SQLite journal is
    inspected within the same transaction as the read/exchange.
    """
    require_carrier_stream_table(table)
    count, first, latest, total, invalid = conn.execute(
        f"SELECT count(*),coalesce(min(seq),0),coalesce(max(seq),0),"
        f"coalesce(sum(length(content)),0),"
        f"coalesce(sum(CASE WHEN typeof(content) != 'blob' "
        f"OR length(content) NOT BETWEEN 1 AND ? THEN 1 ELSE 0 END),0) "
        f"FROM {table}",
        (MAX_CHUNK,),
    ).fetchone()
    if count and (first != 1 or count != latest):
        raise ValueError("carrier journal sequence gap")
    if invalid or total > MAX_TOTAL:
        raise ValueError("invalid durable carrier frame")


def require_contiguous_carrier_rows(conn, table, after, rows):
    """Fail closed if a resumed opaque byte stream would silently skip a frame.

    This checks the acknowledged cursor and requested window. Callers also
    validate the complete bounded historical prefix before resuming.
    The only admitted table names are the carrier's fixed internal journals.
    """
    require_carrier_stream_table(table)
    if after:
        # The caller's cursor acknowledges the immediately preceding durable
        # frame. Even if the next window is valid (or empty), a corrupted
        # acknowledged frame must not be silently treated as delivered.
        cursor = conn.execute(
            f"SELECT content FROM {table} WHERE seq=?", (after,)).fetchone()
        if cursor is None:
            raise ValueError("carrier journal sequence gap")
        if type(cursor[0]) is not bytes or not 1 <= len(cursor[0]) <= MAX_CHUNK:
            raise ValueError("invalid durable carrier frame")
    expected = after + 1
    for seq, payload in rows:
        if seq != expected:
            raise ValueError("carrier journal sequence gap")
        # A damaged SQLite journal may retain contiguous sequence keys but
        # contain TEXT, empty BLOBs, or oversized ciphertext. Validate every
        # frame while the exchange transaction can still roll back inbound
        # admission, not after commit during response encoding.
        if type(payload) is not bytes or not 1 <= len(payload) <= MAX_CHUNK:
            raise ValueError("invalid durable carrier frame")
        expected += 1


def publish(state, table, payload):
    require_carrier_stream_table(table)
    # Only nonempty bounded TLS ciphertext frames are transportable: the
    # receiver rejects empty and >MAX_CHUNK packets. Enforce before opening
    # the journal so no undeliverable outbound sequence can be committed.
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_CHUNK:
        raise ValueError("invalid outbound carrier frame")
    with dbtransaction(state) as conn:
        # A historical journal containing TEXT, an empty BLOB or an
        # oversized frame cannot be extended into a supposedly usable TLS
        # stream. Validate durable payload custody in the same transaction
        # as the append; quota and sequence checks alone are insufficient.
        count, first, latest, total, invalid = conn.execute(
            f"SELECT count(*), coalesce(min(seq),0), coalesce(max(seq),0), "
            f"coalesce(sum(length(content)),0), "
            f"coalesce(sum(CASE WHEN typeof(content) != 'blob' "
            f"OR length(content) NOT BETWEEN 1 AND ? THEN 1 ELSE 0 END),0) "
            f"FROM {table}",
            (MAX_CHUNK,),
        ).fetchone()
        # SQLite sequence keys are signed 64-bit. Exhaustion must be a
        # controlled carrier rejection, not a Python-to-SQLite OverflowError.
        if latest >= (1 << 63) - 1:
            raise ValueError("carrier sequence exhausted")
        # A damaged historical stream must not be extended: a new append
        # cannot repair missing, zero, or negative sequence identities.
        # Check within the same transaction as the new ciphertext write.
        if count and (first != 1 or count != latest):
            raise ValueError("carrier journal sequence gap")
        if invalid:
            raise ValueError("invalid durable carrier frame")
        if total + len(payload) > MAX_TOTAL:
            raise RuntimeError("bounded carrier byte quota exhausted")
        conn.execute(f"INSERT INTO {table}(seq,content) VALUES (?,?)",
                     (latest + 1, payload))

def pull(state, table, after, limit):
    require_carrier_stream_table(table)
    if type(after) is not int or not 0 <= after <= (1 << 63) - 1:
        raise ValueError("invalid carrier cursor")
    if type(limit) is not int or not 1 <= limit <= MAX_BATCH:
        raise ValueError("invalid carrier batch limit")
    with dbtransaction(state) as conn:
        require_healthy_carrier_history(conn, table)
        # A cursor ahead of this durable journal cannot be a successful
        # resume. Silently returning [] would conceal missing TLS frames.
        latest = conn.execute(f"SELECT coalesce(max(seq),0) FROM {table}").fetchone()[0]
        if after > latest:
            raise ValueError("carrier cursor exceeds durable sequence")
        rows = conn.execute(f"SELECT seq,content FROM {table} WHERE seq>? ORDER BY seq LIMIT ?",(after,limit)).fetchall()
        require_contiguous_carrier_rows(conn, table, after, rows)
    return [{"seq":seq,"b64":base64.b64encode(buf).decode("ascii")} for seq,buf in rows]

def require_durable_outbound_cursor(conn, after):
    # Validate the caller's journal cursor before any exchange mutation.
    # A cursor from another session cannot acknowledge nonexistent bytes.
    if type(after) is not int or not 0 <= after <= (1 << 63) - 1:
        raise ValueError("invalid outbound cursor")
    durable_latest = conn.execute("SELECT coalesce(max(seq),0) FROM outbound").fetchone()[0]
    if after > durable_latest:
        raise ValueError("outbound cursor exceeds durable sequence")


def outbound_snapshot_rows(conn, after):
    """Validate the durable outbound history before acknowledging inbound bytes."""
    require_durable_outbound_cursor(conn, after)
    require_healthy_carrier_history(conn, "outbound")
    rows = conn.execute(
        "SELECT seq,content FROM outbound WHERE seq>? ORDER BY seq LIMIT ?",
        (after, MAX_BATCH),
    ).fetchall()
    require_contiguous_carrier_rows(conn, "outbound", after, rows)
    return rows


def emit_outbound_snapshot(rows, after):
    """Emit only the already-validated durable outbound window."""
    packets = [{"seq": seq, "b64": base64.b64encode(buf).decode("ascii")}
               for seq, buf in rows]
    print(json.dumps({"packets": packets, "count": len(packets),
                      "latest": packets[-1]["seq"] if packets else after},
                     separators=(",", ":")))


def snapshot(state, after):
    with dbtransaction(state) as conn:
        rows = outbound_snapshot_rows(conn, after)
    emit_outbound_snapshot(rows, after)

def decode_packet_batch(document):
    if not isinstance(document, str) or len(document) > MAX_BATCH * (MAX_ENCODED_CHUNK + 64) + 2:
        raise ValueError("invalid packet batch")
    # A packet batch has only an array and flat packet objects. Bound nesting
    # before json.loads: parser recursion limits vary across Python releases.
    # Brackets inside quoted JSON strings (including escaped quotes) are inert.
    depth = 0
    quoted = False
    escaped = False
    for char in document:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 2:
                raise ValueError("invalid packet batch nesting")
        elif char in "]}":
            depth -= 1
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate packet key")
            result[key] = value
        return result
    try:
        return json.loads(document, object_pairs_hook=unique)
    except RecursionError as error:
        # A bounded byte count does not bound JSON nesting. Convert parser
        # stack exhaustion into a controlled, fail-closed RPC input error.
        raise ValueError("invalid packet batch nesting") from error

def admit_packet_batch(document):
    """Validate every untrusted frame before acquiring SQLite custody."""
    rows = decode_packet_batch(document)
    if not isinstance(rows, list) or len(rows) > MAX_BATCH:
        raise ValueError("invalid packet batch")
    decoded = []
    previous_seq = 0
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"seq", "b64"}
                or type(row["seq"]) is not int
                or not 1 <= row["seq"] <= (1 << 63) - 1
                or not isinstance(row["b64"], str)):
            raise ValueError("invalid packet schema")
        # The caller's array is a transport-order window, not a set of
        # SQLite keys. Reject intra-batch duplicates and reversed replay
        # before acquiring durable state; complete ordered replays remain
        # idempotent in commit_admitted_inbound.
        if row["seq"] <= previous_seq:
            raise ValueError("packet batch sequence must be strictly increasing")
        previous_seq = row["seq"]
        if len(row["b64"]) > MAX_ENCODED_CHUNK:
            raise ValueError("invalid packet size")
        try:
            packet = base64.b64decode(row["b64"], validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("invalid packet encoding") from error
        if not packet or len(packet) > MAX_CHUNK:
            raise ValueError("invalid packet size")
        # Strict base64 decoding accepts nonzero unused pad bits on some
        # Python versions. Pin the unique RFC 4648 representation before
        # SQLite admission; our own snapshot/pull always emits this form.
        if base64.b64encode(packet).decode("ascii") != row["b64"]:
            raise ValueError("noncanonical packet encoding")
        decoded.append(packet)
    return rows, decoded


def commit_admitted_inbound(conn, rows, packets):
    """Commit already-validated frames in the caller's SQLite transaction."""
    # A historical gap or nonpositive sequence must not be concealed by
    # acknowledging a newer TLS frame. INTEGER PRIMARY KEY identities are
    # unique; a positive journal beginning at one is contiguous exactly when
    # its row count equals its maximum sequence. Check within this transaction
    # before any new inbound write or replay acknowledgement.
    count, first, latest, total, invalid = conn.execute(
        "SELECT count(*),coalesce(min(seq),0),coalesce(max(seq),0),"
        "coalesce(sum(length(content)),0),"
        "coalesce(sum(CASE WHEN typeof(content) != 'blob' "
        "OR length(content) NOT BETWEEN 1 AND ? THEN 1 ELSE 0 END),0) "
        "FROM inbound",
        (MAX_CHUNK,),
    ).fetchone()
    if count and (first != 1 or count != latest):
        raise ValueError("carrier journal sequence gap")
    # A contiguous SQLite journal is not necessarily valid ciphertext.
    # Reject historical TEXT/empty/oversized frames before acknowledging
    # any newer packet, even when the damaged frame is not replayed.
    if invalid or total > MAX_TOTAL:
        raise ValueError("invalid durable inbound carrier frame")
    for row, packet in zip(rows, packets):
        seq=row["seq"]
        if seq <= latest:
            old=conn.execute("SELECT content FROM inbound WHERE seq=?",(seq,)).fetchone()
            if old is None or old[0]!=packet:
                raise ValueError("non-idempotent packet replay")
        elif seq == latest+1:
            if total+len(packet)>MAX_TOTAL:
                raise ValueError("bounded carrier byte quota exhausted")
            conn.execute("INSERT INTO inbound(seq,content) VALUES (?,?)",(seq,packet))
            latest=seq
            total+=len(packet)
        else:
            raise ValueError("out-of-order packet sequence")
    return latest


def deliver(state, document):
    # Reject untrusted RPC bytes before acquiring SQLite custody.
    rows, packets = admit_packet_batch(document)
    with dbtransaction(state) as conn:
        if rows:
            require_open_carrier_lifetime(state)
        latest = commit_admitted_inbound(conn, rows, packets)
    print(json.dumps({"accepted_through":latest,"authority":"none","transport":"external_oracle_rpc"}))

def deliver_quiet(state, packets):
    from contextlib import redirect_stdout
    from io import StringIO
    with redirect_stdout(StringIO()):
        deliver(state,json.dumps(packets,separators=(",",":")))

def require_open_carrier_lifetime(state):
    """Reject delayed inbound RPCs after the native TLS socket has ended.

    Called under the cross-process admission lock. The final EOF check and
    ended-marker creation hold that same lock, so a concurrent RPC cannot
    commit a new ciphertext frame between successful closure and its marker.
    Read-only snapshots remain available to drain already durable outbound.
    """
    if admitted_lifecycle_marker(Path(state) / "ended.json"):
        raise ValueError("carrier lifetime ended")


def write_exclusive_marker(path, document):
    """Create a private lifecycle marker without following or replacing aliases."""
    fd = os.open(path, exclusive_open_flags(os.O_WRONLY), 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(document, file, separators=(",", ":"))
        file.flush()
        os.fsync(file.fileno())
    if os.name == "nt":
        # Elevated Windows tokens may default newly created files to the
        # Administrators owner. Admit only our own new marker as TokenUser.
        windows_claim_new_owner(path)


def admitted_lifecycle_marker(path):
    """Admit a lifecycle marker only while its named inode matches an open handle."""
    try:
        identity = path.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1
            or is_path_alias(path)):
        raise ValueError("real unaliased carrier lifecycle marker required")
    require_private_custody(path, identity, "lifecycle marker")
    # The initial lstat alone can describe a file replaced before status
    # returns. O_NONBLOCK also prevents a raced FIFO from hanging the RPC.
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ValueError("carrier lifecycle marker changed during admission") from error
    try:
        opened = os.fstat(fd)
        try:
            current = path.lstat()
        except OSError as error:
            # A marker removed after open must fail closed as an admission
            # error, not escape the Oracle RPC as an unhandled filesystem race.
            raise ValueError("carrier lifecycle marker identity changed") from error
        def marker_identity(value):
            return (value.st_dev, value.st_ino, value.st_mode,
                    value.st_nlink, value.st_uid, value.st_gid)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or marker_identity(identity) != marker_identity(opened)
                or marker_identity(opened) != marker_identity(current)
                or is_path_alias(path)):
            raise ValueError("carrier lifecycle marker identity changed")
        require_private_custody(path, opened, "lifecycle marker")
        require_private_custody(path, current, "lifecycle marker")
        # An exclusive marker may be observed between O_EXCL creation and
        # fsync, or after a crash left a truncated document. A private inode
        # alone cannot attest a ready/ended lifecycle event. Read only from
        # the already admitted descriptor, with a small fixed size ceiling.
        payload = os.read(fd, 4097)
        if not payload or len(payload) > 4096:
            raise ValueError("invalid carrier lifecycle marker content")
        def unique_fields(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate carrier lifecycle marker key")
                result[key] = value
            return result
        def reject_nonfinite(value):
            raise ValueError("nonfinite carrier lifecycle marker value")
        def finite_float(token):
            # json.loads accepts 1e999 as float("inf") without calling
            # parse_constant. Reject overflow at every nesting depth.
            value = float(token)
            if not math.isfinite(value):
                raise ValueError("nonfinite carrier lifecycle marker value")
            return value
        try:
            document = json.loads(payload, object_pairs_hook=unique_fields,
                                  parse_constant=reject_nonfinite,
                                  parse_float=finite_float)
        except (ValueError, UnicodeError) as error:
            raise ValueError("invalid carrier lifecycle marker content") from error
        if type(document) is not dict or not document:
            raise ValueError("invalid carrier lifecycle marker content")
        # Private JSON alone is not evidence of a native TLS socket event.
        # Only serve() writes these two exact event shapes. In particular,
        # an incomplete ready marker must not be reported as a live carrier,
        # and a contradictory end marker must not certify completion.
        if path.name == "ready.json":
            valid = (set(document) == {"mode", "port", "pid", "bound"}
                     and document["mode"] in ("accept", "dial")
                     and type(document["port"]) is int
                     and 1024 <= document["port"] <= 65535
                     and type(document["pid"]) is int and document["pid"] > 0
                     and document["bound"] == "127.0.0.1")
        elif path.name == "ended.json":
            valid = (set(document) == {"pid", "finished", "failed"}
                     and type(document["pid"]) is int and document["pid"] > 0
                     and type(document["finished"]) is bool
                     and type(document["failed"]) is bool
                     and document["finished"] != document["failed"])
        else:
            valid = False
        if not valid:
            raise ValueError("invalid carrier lifecycle marker schema")
    finally:
        os.close(fd)
    return True


def serve(state, mode, port):
    if mode not in ("accept","dial") or not 1024<=port<=65535:
        raise ValueError("invalid endpoint")
    root=require_unaliased_state_path(state)
    # A prepared carrier belongs to exactly one TLS socket lifetime.
    # The exclusive claim also rejects concurrent attempts before opening a socket.
    if (not root.is_dir() or is_path_alias(root)
            or any(os.path.lexists(root / name) for name in ("ready.json", "ended.json"))):
        raise ValueError("newly prepared carrier state required")
    # Never claim a TLS socket for an unprepared or non-private state. Reuse
    # the same SQLite custody checks as snapshot/deliver before any side effect.
    with dbtransaction(root):
        pass
    try:
        claim_fd=os.open(root/"serve.claim", exclusive_open_flags(os.O_WRONLY), 0o600)
    except FileExistsError:
        raise ValueError("newly prepared carrier state required") from None
    else:
        os.close(claim_fd)
    marker=root/"ready.json"
    sock=None
    listener=None
    started=time.monotonic()
    if mode=="accept":
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(("127.0.0.1",port))
            listener.listen(1)
            listener.settimeout(120)
            write_exclusive_marker(marker, {"mode":mode,"port":port,"pid":os.getpid(),"bound":"127.0.0.1"})
            sock,_=listener.accept()
        except BaseException:
            # A failed listener must not retain a bound port. If readiness
            # was already published, record the failed lifetime so status
            # cannot mistake an abandoned listener for a live TLS carrier.
            listener.close()
            if os.path.lexists(marker) and not os.path.lexists(root/"ended.json"):
                try:
                    write_exclusive_marker(root/"ended.json",
                                           {"pid":os.getpid(),"finished":False,"failed":True})
                except OSError:
                    # Preserve the original accept/marker failure. The
                    # exclusive claim still prevents a second socket.
                    pass
            raise
    else:
        # Dial mode is not ready until a real local Control socket exists.
        # A failed dial retains serve.claim, but must not advertise a ready
        # transport marker that could mislead Oracle-side observations.
        while time.monotonic()-started<120:
            try:
                sock=socket.create_connection(("127.0.0.1",port),timeout=3)
                break
            except OSError:
                time.sleep(.1)
        if sock is None:
            raise RuntimeError("local Control unavailable")
        try:
            write_exclusive_marker(marker, {"mode":mode,"port":port,"pid":os.getpid(),"bound":"127.0.0.1"})
        except BaseException:
            # A connected socket must not leak when marker admission fails.
            sock.close()
            raise
    try:
        sock.settimeout(.1)
    except BaseException:
        # The ready marker already exists. A socket setup failure before
        # pump threads start must release both endpoints and seal a failed
        # lifetime rather than leaving an apparently live carrier.
        sock.close()
        if listener is not None:
            listener.close()
        if os.path.lexists(marker) and not os.path.lexists(root/"ended.json"):
            try:
                write_exclusive_marker(root/"ended.json",
                                       {"pid":os.getpid(),"finished":False,"failed":True})
            except OSError:
                # Keep the original setup failure; the exclusive claim
                # prevents another socket from inheriting this state.
                pass
        raise
    completed=threading.Event()
    failures=[]
    failure_lock=threading.Lock()
    # A clean native socket EOF does not imply that the writer forwarded all
    # durable Oracle inbound ciphertext before the reader stopped both pumps.
    delivered_through = [0]
    def record_failure(role,exc):
        with failure_lock:
            failures.append((role,type(exc).__name__,str(exc)))
        completed.set()
    def reader():
        try:
            while not completed.is_set():
                if time.monotonic()-started>=MAX_RUNTIME:
                    record_failure("timeout", TimeoutError("carrier runtime budget exhausted"))
                    break
                try:
                    chunk=sock.recv(MAX_CHUNK)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                publish(state,"outbound",chunk)
        except Exception as error:
            record_failure("reader",error)
        finally:
            completed.set()
    def writer():
        cursor=0
        try:
            while not completed.is_set():
                if time.monotonic()-started>=MAX_RUNTIME:
                    record_failure("timeout", TimeoutError("carrier runtime budget exhausted"))
                    break
                packets=pull(state,"inbound",cursor,MAX_BATCH)
                for p in packets:
                    sock.sendall(base64.b64decode(p["b64"]))
                    cursor=p["seq"]
                    delivered_through[0] = cursor
                time.sleep(.015)
        except Exception as error:
            record_failure("writer",error)
        finally:
            completed.set()
    a=threading.Thread(target=reader,daemon=True)
    b=threading.Thread(target=writer,daemon=True)
    launched = []
    try:
        a.start()
        launched.append(a)
        b.start()
        launched.append(b)
    except BaseException:
        # Readiness precedes the byte pumps. A failed thread launch must
        # terminate any already-started pump and seal the claimed lifetime.
        completed.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        if listener is not None:
            listener.close()
        for thread in launched:
            thread.join(timeout=3)
        if os.path.lexists(marker) and not os.path.lexists(root / "ended.json"):
            try:
                write_exclusive_marker(root / "ended.json",
                                       {"pid": os.getpid(), "finished": False, "failed": True})
            except OSError:
                # Retain the original launch error and exclusive claim.
                pass
        raise
    while not completed.is_set():
        if time.monotonic()-started>=MAX_RUNTIME:
            record_failure("timeout", TimeoutError("carrier runtime budget exhausted"))
            break
        time.sleep(.08)
    completed.set()
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()
    if listener is not None:
        listener.close()
    a.join(timeout=3)
    b.join(timeout=3)
    if a.is_alive() or b.is_alive():
        record_failure("shutdown",RuntimeError("carrier byte pump did not terminate"))
    # The reader can observe EOF before the writer polls already admitted
    # inbound TLS bytes. The final history check and ended marker MUST share
    # the same admission lock as deliver/exchange. Otherwise an Oracle RPC
    # can commit a new frame after the check but before the marker, producing
    # a false successful socket-lifetime record.
    try:
        with dbtransaction(state) as conn:
            if not failures:
                try:
                    require_healthy_carrier_history(conn, "inbound")
                    latest = conn.execute(
                        "SELECT coalesce(max(seq),0) FROM inbound").fetchone()[0]
                    if latest > delivered_through[0]:
                        record_failure("undelivered", RuntimeError(
                            "durable inbound frames not forwarded to native socket"))
                except Exception as error:
                    record_failure("finalize", error)
            status={"pid":os.getpid(),"finished":not failures,"failed":bool(failures)}
            write_exclusive_marker(root/"ended.json", status)
    except Exception as error:
        record_failure("finalize", error)
        # An unavailable database cannot justify a success marker. Preserve
        # a failed marker when possible without replacing an existing alias.
        if not os.path.lexists(root/"ended.json"):
            write_exclusive_marker(root/"ended.json",
                                   {"pid":os.getpid(),"finished":False,"failed":True})
    if failures:
        first=failures[0]
        raise RuntimeError("E07_CARRIER_PUMP_FAILED:"+first[0]+":"+first[1]+":"+first[2])

def main():
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest="command",required=True)
    for name in ("prepare","snapshot","deliver","serve","status","exchange"):
        child=sub.add_parser(name)
        child.add_argument("--state",required=True)
        if name in ("snapshot","exchange"):
            child.add_argument("--after",type=int,default=0)
        if name in ("deliver","exchange"):
            child.add_argument("--packets",required=True)
        if name=="serve":
            child.add_argument("--mode",choices=["accept","dial"],required=True)
            child.add_argument("--port",type=int,required=True)
    a=parser.parse_args()
    if a.command=="prepare": prepare(a.state)
    elif a.command=="snapshot": snapshot(a.state,a.after)
    elif a.command=="deliver": deliver(a.state,a.packets)
    elif a.command=="exchange":
        # Single authenticated Oracle invocation both commits inbound and
        # obtains outbound. Reduces per-cycle latency for E01 TLS timeouts.
        # Do not print input ciphertext again or mistake it for commands.
        data, packets = admit_packet_batch(a.packets)
        # Allow the local native pump a short opportunity to publish before
        # taking the snapshot, never between commit and response.
        time.sleep(.04)
        # Bind the returned outbound window to the SAME transaction that
        # commits inbound frames. A second SQLite read after commit could
        # fail on a changed journal despite inbound bytes already persisting.
        with dbtransaction(a.state) as conn:
            rows = outbound_snapshot_rows(conn, a.after)
            # Even an empty polling window must validate the inbound prefix.
            # Otherwise a damaged TLS journal can be reported as a healthy
            # bidirectional exchange without any durable admission check.
            if data:
                require_open_carrier_lifetime(a.state)
            commit_admitted_inbound(conn, data, packets)
        emit_outbound_snapshot(rows, a.after)
    elif a.command=="serve": serve(a.state,a.mode,a.port)
    elif a.command=="status":
        with dbtransaction(a.state) as db:
            # Status is a transport-readiness observation, not merely a row
            # counter. A ready marker cannot rehabilitate a corrupt durable
            # TLS prefix. Validate both streams under the same admission lock
            # and transaction before reporting apparently usable state.
            require_healthy_carrier_history(db, "outbound")
            require_healthy_carrier_history(db, "inbound")
            n1=db.execute("SELECT count(*),coalesce(sum(length(content)),0) FROM outbound").fetchone()
            n2=db.execute("SELECT count(*),coalesce(sum(length(content)),0) FROM inbound").fetchone()
        root = require_unaliased_state_path(a.state)
        print(json.dumps({"outbound": n1, "inbound": n2,
                          "ready": admitted_lifecycle_marker(root / "ready.json"),
                          "ended": admitted_lifecycle_marker(root / "ended.json")}))

if __name__=="__main__":
    try: main()
    except (ValueError,RuntimeError,OSError,sqlite3.Error) as e:
        print(json.dumps({"error":str(e)}),file=sys.stderr)
        sys.exit(2)
