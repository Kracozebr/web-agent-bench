"""Two offline BER history replays and tampered/missing COPY rejection probes.

Never connects to PostgreSQL/BEF or invokes a worker. Database fingerprints must
be independently collected before/after this process to prove the scoped DB window.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.bdd.adapters.ber_recovery_replay import canonical, digest, read_reference, verify_native_recovery_history


def now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def run(reference: dict, *, repository_root: Path = ROOT, required_modes: list[str] | None = None) -> dict:
    root=repository_root.resolve(strict=True)
    started=now()
    packet=read_reference(root,reference)
    files={reference["path"],*packet["sourceHashes"],*(a["path"] for a in packet["artifacts"])}
    files.update({"tests/bdd/adapters/ber_recovery_replay.py","tools/replay_ber_recovery.py"})
    before={p:sha(root/p) for p in sorted(files)}
    pass_one_start=now()
    first=verify_native_recovery_history(reference,repository_root=root,required_modes=required_modes)
    pass_one_end=now()
    pass_two_start=now()
    second=verify_native_recovery_history(reference,repository_root=root,required_modes=required_modes)
    pass_two_end=now()
    if first!=second: raise AssertionError("replay outputs differ")
    target=next(a for a in packet["artifacts"] if a["path"]==packet["runs"][0]["rows"]["receipts"][0]["evidence_path"])
    local=root/".local"
    local.mkdir(exist_ok=True)
    negative_results={}
    with tempfile.TemporaryDirectory(prefix="ber-replay-negative-",dir=local) as temporary:
        copy_root=Path(temporary).resolve(strict=True)
        if copy_root.parent != local.resolve(strict=True): raise AssertionError("temporary copy escaped local workspace")
        for p in files:
            dest=copy_root/p
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(root/p,dest)
        # A genuine byte copy must pass first, otherwise a negative could be vacuous.
        if verify_native_recovery_history(reference,repository_root=copy_root,required_modes=required_modes)!=first:
            raise AssertionError("unmodified copied proof differs")
        target_path=copy_root/target["path"]
        original=target_path.read_bytes()
        for name,mutation in [("tampered_raw_artifact",lambda:target_path.write_bytes(original+b"\n ")),
                              ("missing_raw_artifact",lambda:target_path.unlink())]:
            target_path.write_bytes(original)
            mutation()
            try:
                verify_native_recovery_history(reference,repository_root=copy_root,required_modes=required_modes)
            except (AssertionError,FileNotFoundError) as error:
                negative_results[name]={"status":"rejected","errorKind":type(error).__name__}
            else:
                raise AssertionError(name+" was accepted")
        # Recomputed byte hashes must not permit a different execution generation.
        target_path.write_bytes(original)
        changed=json.loads(original)
        changed["generationId"]=str(uuid.uuid4())
        changed_bytes=json.dumps(changed,separators=(",",":"),ensure_ascii=False).encode()
        target_path.write_bytes(changed_bytes)
        changed_sha=hashlib.sha256(changed_bytes).hexdigest()
        copied=json.loads(json.dumps(packet))
        for artifact in copied["artifacts"]:
            if artifact["path"]==target["path"]:
                artifact.update(sha256=changed_sha,sizeBytes=len(changed_bytes))
        rows=copied["runs"][0]["rows"]
        for name in ["receipts","reconciliations"]:
            for receipt in rows[name]:
                if receipt["evidence_path"]==target["path"]: receipt["evidence_hash"]=changed_sha
            copied["runs"][0]["sets"][name]={"count":len(rows[name]),"sha256":digest(sorted(rows[name],key=canonical))}
        raw=json.dumps(copied,separators=(",",":"),ensure_ascii=False).encode()
        (copy_root/reference["path"]).write_bytes(raw)
        changed_reference={"path":reference["path"],"sha256":hashlib.sha256(raw).hexdigest()}
        try:
            verify_native_recovery_history(changed_reference,repository_root=copy_root,required_modes=required_modes)
        except AssertionError as error:
            negative_results["wrong_generation_with_recomputed_hashes"]={"status":"rejected","errorKind":type(error).__name__}
        else:
            raise AssertionError("wrong-generation proof accepted with recomputed hashes")
    after={p:sha(root/p) for p in sorted(files)}
    if before!=after: raise AssertionError("business evidence or source file changed during offline replay")
    return {"schemaVersion":"ber-independent-two-replay-report/v1","startedAt":started,"finishedAt":now(),
            "capture":reference,"requiredModes":required_modes or ["ranked","training"],"readerSourceSha256":before["tests/bdd/adapters/ber_recovery_replay.py"],
            "runnerSourceSha256":before["tools/replay_ber_recovery.py"],"twoReplayOutputsEqual":True,
            "filesystemInputsUnchanged":True,"checkedFiles":len(files),"inputFingerprints":before,
            "inputFingerprintsAfter":after,"passes":[
                {"startedAt":pass_one_start,"finishedAt":pass_one_end,"output":first,"outputSha256":digest(first)},
                {"startedAt":pass_two_start,"finishedAt":pass_two_end,"output":second,"outputSha256":digest(second)}],
            "negativeCopies":negative_results,"reconstructedHistory":first,
            "databaseWriteProof":"requires_separate_readonly_fingerprints_surrounding_this_report",
            "fullScenarioAcceptance":"blocked"}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture",required=True)
    parser.add_argument("--sha256",required=True)
    parser.add_argument("--required-mode",choices=["training","ranked"])
    args=parser.parse_args()
    result=run({"path":args.capture,"sha256":args.sha256},required_modes=[args.required_mode] if args.required_mode else None)
    out=ROOT/"artifacts"/"runs"/"ber-independent-two-replay"/str(uuid.uuid4())
    out.mkdir(parents=True,exist_ok=False)
    path=out/"verification.json"
    data=(json.dumps(result,indent=2,ensure_ascii=False)+"\n").encode()
    with path.open("xb") as file: file.write(data)
    print(json.dumps({"path":path.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(data).hexdigest(),
                      "twoReplayOutputsEqual":True,"filesystemInputsUnchanged":True,"negativeCopies":result["negativeCopies"],
                      "fullScenarioAcceptance":"blocked"}))
