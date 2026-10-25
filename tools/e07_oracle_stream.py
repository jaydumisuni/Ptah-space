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
import hashlib
import json
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
    require_private_custody(root, root.stat(), "state directory")
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
    fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
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
            except (OSError, BlockingIOError) as error:
                if time.monotonic() >= deadline:
                    raise TimeoutError("carrier admission lock busy") from error
                time.sleep(0.02)
        try:
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
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
        conn.execute("PRAGMA journal_mode=WAL")
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


def publish(state, table, payload):
    require_carrier_stream_table(table)
    # Only nonempty bounded TLS ciphertext frames are transportable: the
    # receiver rejects empty and >MAX_CHUNK packets. Enforce before opening
    # the journal so no undeliverable outbound sequence can be committed.
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_CHUNK:
        raise ValueError("invalid outbound carrier frame")
    with dbtransaction(state) as conn:
        row = conn.execute(f"SELECT coalesce(sum(length(content)),0), coalesce(max(seq),0) FROM {table}").fetchone()
        if row[0]+len(payload)>MAX_TOTAL:
            raise RuntimeError("bounded carrier byte quota exhausted")
        conn.execute(f"INSERT INTO {table}(seq,content) VALUES (?,?)",(row[1]+1,payload))

def pull(state, table, after, limit):
    require_carrier_stream_table(table)
    if type(after) is not int or not 0 <= after <= (1 << 63) - 1:
        raise ValueError("invalid carrier cursor")
    if type(limit) is not int or not 1 <= limit <= MAX_BATCH:
        raise ValueError("invalid carrier batch limit")
    with dbtransaction(state) as conn:
        rows = conn.execute(f"SELECT seq,content FROM {table} WHERE seq>? ORDER BY seq LIMIT ?",(after,limit)).fetchall()
    return [{"seq":seq,"b64":base64.b64encode(buf).decode("ascii")} for seq,buf in rows]

def validate_outbound_cursor(conn, after):
    """Reject a cursor from another carrier before accepting inbound bytes."""
    if type(after) is not int or not 0 <= after <= (1 << 63) - 1:
        raise ValueError("invalid outbound cursor")
    durable_latest = conn.execute("SELECT coalesce(max(seq),0) FROM outbound").fetchone()[0]
    if after > durable_latest:
        raise ValueError("outbound cursor exceeds durable sequence")

def snapshot(state, after):
    # An over-advanced caller cursor is not evidence that these opaque TLS
    # bytes were ever published. Reject it instead of echoing a fabricated
    # latest sequence across an Oracle RPC/restarted carrier session.
    if type(after) is not int or not 0 <= after <= (1 << 63) - 1:
        raise ValueError("invalid outbound cursor")
    with dbtransaction(state) as conn:
        validate_outbound_cursor(conn, after)
        rows = conn.execute(
            "SELECT seq,content FROM outbound WHERE seq>? ORDER BY seq LIMIT ?",
            (after, MAX_BATCH),
        ).fetchall()
    packets = [{"seq": seq, "b64": base64.b64encode(buf).decode("ascii")}
               for seq, buf in rows]
    print(json.dumps({"packets": packets, "count": len(packets),
                      "latest": packets[-1]["seq"] if packets else after},
                     separators=(",", ":")))

def decode_packet_batch(document):
    if not isinstance(document, str) or len(document) > MAX_BATCH * (MAX_ENCODED_CHUNK + 64) + 2:
        raise ValueError("invalid packet batch")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate packet key")
            result[key] = value
        return result
    return json.loads(document, object_pairs_hook=unique)

def deliver(state, document):
    # Reject oversized RPC envelopes before parsing or decoding attacker-supplied bytes.
    if not isinstance(document, str) or len(document) > MAX_BATCH * (MAX_ENCODED_CHUNK + 64) + 2:
        raise ValueError("invalid packet batch")
    rows=decode_packet_batch(document)
    if not isinstance(rows,list) or len(rows)>MAX_BATCH:
        raise ValueError("invalid packet batch")
    with dbtransaction(state) as conn:
        latest=conn.execute("SELECT coalesce(max(seq),0) FROM inbound").fetchone()[0]
        total=conn.execute("SELECT coalesce(sum(length(content)),0) FROM inbound").fetchone()[0]
        for row in rows:
            if (not isinstance(row,dict) or set(row)!={"seq","b64"}
                    or type(row["seq"]) is not int or not isinstance(row["b64"],str)):
                raise ValueError("invalid packet schema")
            if len(row["b64"]) > MAX_ENCODED_CHUNK:
                raise ValueError("invalid packet size")
            try:
                packet=base64.b64decode(row["b64"],validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError("invalid packet encoding") from error
            if not packet or len(packet)>MAX_CHUNK:
                raise ValueError("invalid packet size")
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
    print(json.dumps({"accepted_through":latest,"authority":"none","transport":"external_oracle_rpc"}))

def deliver_quiet(state, packets):
    from contextlib import redirect_stdout
    from io import StringIO
    with redirect_stdout(StringIO()):
        deliver(state,json.dumps(packets,separators=(",",":")))

def admitted_lifecycle_marker(root, name):
    """Report a lifecycle marker only after private, unaliased inode admission.

    Marker presence is historical evidence, not proof of a live TLS socket.
    """
    marker = root / name
    try:
        identity = marker.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1
            or is_path_alias(marker)):
        raise ValueError("real unaliased carrier lifecycle marker required")
    require_private_custody(marker, identity, "lifecycle marker")
    # Opening nonblocking and no-follow prevents FIFO/symlink substitution
    # from turning a read-only status RPC into a hang or alias admission.
    fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        named = marker.lstat()
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (identity.st_dev, identity.st_ino)
                or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
                or is_path_alias(marker)):
            raise ValueError("carrier lifecycle marker identity changed")
        require_private_custody(marker, opened, "lifecycle marker")
        require_private_custody(marker, named, "lifecycle marker")
    finally:
        os.close(fd)
    return True


def write_exclusive_marker(path, document):
    """Create a private lifecycle marker without following or replacing aliases."""
    fd = os.open(path, exclusive_open_flags(os.O_WRONLY), 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(document, file, separators=(",", ":"))
        file.flush()
        os.fsync(file.fileno())

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
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(("127.0.0.1",port))
        listener.listen(1)
        listener.settimeout(120)
        write_exclusive_marker(marker, {"mode":mode,"port":port,"pid":os.getpid(),"bound":"127.0.0.1"})
        sock,_=listener.accept()
    else:
        write_exclusive_marker(marker, {"mode":mode,"port":port,"pid":os.getpid(),"bound":"127.0.0.1"})
        while time.monotonic()-started<120:
            try:
                sock=socket.create_connection(("127.0.0.1",port),timeout=3)
                break
            except OSError:
                time.sleep(.1)
        if sock is None:
            raise RuntimeError("local Control unavailable")
    sock.settimeout(.1)
    completed=threading.Event()
    failures=[]
    failure_lock=threading.Lock()
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
                time.sleep(.015)
        except Exception as error:
            record_failure("writer",error)
        finally:
            completed.set()
    a=threading.Thread(target=reader,daemon=True)
    b=threading.Thread(target=writer,daemon=True)
    a.start()
    b.start()
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
    status={"pid":os.getpid(),"finished":not failures,"failed":bool(failures)}
    write_exclusive_marker(root/"ended.json", status)
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
        data=decode_packet_batch(a.packets)
        if not isinstance(data, list) or len(data) > MAX_BATCH:
            raise ValueError("invalid packet batch")
        # Validate outbound custody before committing any inbound ciphertext.
        # The final snapshot repeats this check after delivery.
        with dbtransaction(a.state) as conn:
            validate_outbound_cursor(conn, a.after)
        if data: deliver_quiet(a.state,data)
        time.sleep(.04)
        snapshot(a.state,a.after)
    elif a.command=="serve": serve(a.state,a.mode,a.port)
    elif a.command=="status":
        with dbtransaction(a.state) as db:
            n1=db.execute("SELECT count(*),coalesce(sum(length(content)),0) FROM outbound").fetchone()
            n2=db.execute("SELECT count(*),coalesce(sum(length(content)),0) FROM inbound").fetchone()
        print(json.dumps({"outbound":n1,"inbound":n2,
                          "ready":admitted_lifecycle_marker(Path(a.state), "ready.json"),
                          "ended":admitted_lifecycle_marker(Path(a.state), "ended.json")}))

if __name__=="__main__":
    try: main()
    except (ValueError,RuntimeError,OSError,sqlite3.Error) as e:
        print(json.dumps({"error":str(e)}),file=sys.stderr)
        sys.exit(2)
