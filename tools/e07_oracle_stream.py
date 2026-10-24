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

MAX_CHUNK = 32768
MAX_ENCODED_CHUNK = 4 * ((MAX_CHUNK + 2) // 3)
MAX_BATCH = 32
MAX_TOTAL = 8 * 1024 * 1024
MAX_RUNTIME = 300

def require_unaliased_state_path(state):
    # Preserve lexical path identity: resolving first would hide symlink parents.
    root = Path(state)
    if not root.is_absolute():
        raise ValueError("absolute carrier state path required")
    if ".." in root.parts:
        raise ValueError("carrier state parent traversal prohibited")
    if any(parent.is_symlink() for parent in root.parents):
        raise ValueError("symlinked carrier state ancestor prohibited")
    return root

def dbconnect(state, create=False):
    root = require_unaliased_state_path(state)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("existing real state directory required")
    root_identity = root.stat()
    if root_identity.st_uid != os.geteuid():
        raise ValueError("private carrier state owner required")
    if stat.S_IMODE(root_identity.st_mode) & 0o077:
        raise ValueError("private carrier state directory required")
    db_path = root / "carrier.sqlite3"
    if create:
        # Only prepare may create a database, and never over an existing alias.
        fd = os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    try:
        identity = db_path.lstat()
    except FileNotFoundError:
        raise ValueError("prepared carrier database required") from None
    if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1:
        raise ValueError("real unaliased carrier database required")
    if identity.st_uid != os.geteuid():
        raise ValueError("private carrier database owner required")
    if stat.S_IMODE(identity.st_mode) & 0o077:
        raise ValueError("private carrier database required")
    # SQLite may open these companion files implicitly. Reject pre-existing
    # aliases before giving SQLite the path; this is not a race-free dirfd
    # custody proof and does not replace independent E07 qualification.
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = db_path.with_name(db_path.name + suffix)
        try:
            sidecar_identity = sidecar.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(sidecar_identity.st_mode) or sidecar_identity.st_nlink != 1:
            raise ValueError("real unaliased carrier sidecar required")
        if sidecar_identity.st_uid != os.geteuid():
            raise ValueError("private carrier sidecar owner required")
        if stat.S_IMODE(sidecar_identity.st_mode) & 0o077:
            raise ValueError("private carrier sidecar required")
    conn = sqlite3.connect(str(db_path), timeout=7)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=7000")
    conn.execute("CREATE TABLE IF NOT EXISTS outbound(seq INTEGER PRIMARY KEY, content BLOB NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS inbound(seq INTEGER PRIMARY KEY, content BLOB NOT NULL)")
    conn.commit()
    return conn

@contextmanager
def dbtransaction(state):
    """Commit or roll back each operation and always release its SQLite handle."""
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
    conn = dbconnect(p, create=True)
    conn.close()
    print(json.dumps({"state":str(p),"new":True,"listener":"loopback_only"}))

def publish(state, table, payload):
    with dbtransaction(state) as conn:
        row = conn.execute(f"SELECT coalesce(sum(length(content)),0), coalesce(max(seq),0) FROM {table}").fetchone()
        if row[0]+len(payload)>MAX_TOTAL:
            raise RuntimeError("bounded carrier byte quota exhausted")
        conn.execute(f"INSERT INTO {table}(seq,content) VALUES (?,?)",(row[1]+1,payload))

def pull(state, table, after, limit):
    with dbtransaction(state) as conn:
        rows = conn.execute(f"SELECT seq,content FROM {table} WHERE seq>? ORDER BY seq LIMIT ?",(after,limit)).fetchall()
    return [{"seq":seq,"b64":base64.b64encode(buf).decode("ascii")} for seq,buf in rows]

def snapshot(state, after):
    rows=pull(state,"outbound",after,MAX_BATCH)
    print(json.dumps({"packets":rows,"count":len(rows),"latest":rows[-1]["seq"] if rows else after},separators=(",",":")))

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

def write_exclusive_marker(path, document):
    """Create a private lifecycle marker without following or replacing aliases."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
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
    if (not root.is_dir() or root.is_symlink()
            or any(os.path.lexists(root / name) for name in ("ready.json", "ended.json"))):
        raise ValueError("newly prepared carrier state required")
    # Never claim a TLS socket for an unprepared or non-private state. Reuse
    # the same SQLite custody checks as snapshot/deliver before any side effect.
    with dbtransaction(root):
        pass
    try:
        claim_fd=os.open(root/"serve.claim", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
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
            while not completed.is_set() and time.monotonic()-started<MAX_RUNTIME:
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
            while not completed.is_set() and time.monotonic()-started<MAX_RUNTIME:
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
    while not completed.is_set() and time.monotonic()-started<MAX_RUNTIME:
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
        if data: deliver_quiet(a.state,data)
        time.sleep(.04)
        snapshot(a.state,a.after)
    elif a.command=="serve": serve(a.state,a.mode,a.port)
    elif a.command=="status":
        with dbtransaction(a.state) as db:
            n1=db.execute("SELECT count(*),coalesce(sum(length(content)),0) FROM outbound").fetchone()
            n2=db.execute("SELECT count(*),coalesce(sum(length(content)),0) FROM inbound").fetchone()
        print(json.dumps({"outbound":n1,"inbound":n2,"ready":(Path(a.state)/"ready.json").exists(),"ended":(Path(a.state)/"ended.json").exists()}))

if __name__=="__main__":
    try: main()
    except (ValueError,RuntimeError,OSError,sqlite3.Error) as e:
        print(json.dumps({"error":str(e)}),file=sys.stderr)
        sys.exit(2)
