"""Run a real Ptah Control checkpoint submission and restart readback."""
import argparse
import json
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from ptah_control_client import PtahControlClient, PtahBoundaryError

def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)

def qualify(binary, fixture):
    if not binary.is_file() or not fixture.is_file():
        raise RuntimeError("missing Rust executable or A14 test fixture")
    with tempfile.TemporaryDirectory(prefix="ptah-control-proof-") as dirname:
        root=Path(dirname)
        snapshot=root/"snapshot.json"
        log=root/"submissions.ndjson"
        shutil.copyfile(fixture,snapshot)
        log.write_text("",encoding="utf-8")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0))
            port=sock.getsockname()[1]
        url=f"http://127.0.0.1:{port}"
        argv=[str(binary.resolve()),"serve","--snapshot",str(snapshot),
              "--submissions",str(log),"--listen",f"127.0.0.1:{port}"]
        def start():
            proc=subprocess.Popen(argv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            client=PtahControlClient(url,timeout=2)
            for _ in range(60):
                try:
                    client.observe()
                    return proc,client
                except PtahBoundaryError:
                    if proc.poll() is not None:
                        raise RuntimeError("Control exited during startup")
                    time.sleep(.05)
            stop(proc)
            raise RuntimeError("Control never opened loopback listener")
        first=None
        second=None
        try:
            first,client=start()
            authority=client.observe().authority
            receipt=client.submit_control(kind="checkpoint_request",
                    target_id=authority["workspace_id"],payload={})
            before=client.read_submission(receipt.request_id)
            if before.execution_status!="not_executed_by_this_control_service":
                raise AssertionError("False execution status")
            stop(first)
            first=None
            second,restarted=start()
            after=restarted.read_submission(receipt.request_id)
            if after!=before:
                raise AssertionError("request changed across process restart")
            lines=log.read_text(encoding="utf-8").splitlines()
            if len(lines)!=1:
                raise AssertionError("exact durable submission cardinality lost")
            return {"result":"PASS","request_id":receipt.request_id,
                    "persisted_submissions":len(lines),
                    "execution_status":after.execution_status}
        finally:
            stop(first)
            stop(second)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary",required=True,type=Path)
    parser.add_argument("--fixture",required=True,type=Path)
    opts=parser.parse_args()
    print(json.dumps(qualify(opts.binary,opts.fixture),sort_keys=True))

if __name__=="__main__":
    main()
