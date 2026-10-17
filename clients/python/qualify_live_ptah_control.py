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
from ptah_shared_workspace import SharedWorkspace

def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)

def qualify(binary, fixture, shared_clients=False):
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
            if shared_clients:
                workspace=SharedWorkspace(client)
                callers=("cookpit","supervisor","formula","ttg-simulation","hunter")
                handles={caller:workspace.for_tool(caller,"ptah") for caller in callers}
                receipts={caller:handle.checkpoint({"test":"shared-workspace-restart"})
                          for caller,handle in handles.items()}
                before={caller:handles[caller].readback(receipts[caller])
                        for caller in callers}
            else:
                receipt=client.submit_control(kind="checkpoint_request",
                        target_id=authority["workspace_id"],payload={})
                before=client.read_submission(receipt.request_id)
                if before.execution_status!="not_executed_by_this_control_service":
                    raise AssertionError("False execution status")
            stop(first)
            first=None
            second,restarted=start()
            if shared_clients:
                workspace=SharedWorkspace(restarted)
                after={caller:workspace.for_tool(caller,"ptah").readback(receipts[caller])
                       for caller in callers}
                if after!=before:
                    raise AssertionError("multi-client readback changed across restart")
                expected=len(callers)
            else:
                after=restarted.read_submission(receipt.request_id)
                if after!=before:
                    raise AssertionError("request changed across process restart")
                expected=1
            lines=log.read_text(encoding="utf-8").splitlines()
            if len(lines)!=expected:
                raise AssertionError("exact durable submission cardinality lost")
            if shared_clients:
                names={item["payload"]["caller_context"]["tool"] for item
                       in (json.loads(line) for line in lines)}
                if names!=set(callers):
                    raise AssertionError("caller provenance lost in Control journal")
                return {"result":"PASS","callers":list(callers),
                        "workspace_id":authority["workspace_id"],
                        "persisted_submissions":len(lines),
                        "execution_status":"not_executed_by_this_control_service"}
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
    parser.add_argument("--shared-clients",action="store_true")
    opts=parser.parse_args()
    print(json.dumps(qualify(opts.binary,opts.fixture,opts.shared_clients),sort_keys=True))

if __name__=="__main__":
    main()
