"""Independent BER admitted-action identity replay; never dispatches or grades.

The census is not effect proof. Until independent family/RPC/evaluator captures
are attached and replayed, this module explicitly returns non-passing boundaries.
Synthetic controls test the reader only and cannot qualify environment gates.
"""
import hashlib
import json
import re
from pathlib import Path
from tests.bdd.adapters.ber_recovery_replay import read_reference

KINDS=("inspect_catalog","inspect_offer","pay","retrieve","approve","transfer","wrap","unwrap","swap")
TASKS=("S1","S2","S3","S4","M1","M2","M3","M4","H1","H2","H3","U1")
PATHS=tuple(("training",t) for t in ("S1","M1","H1"))+tuple(("ranked",t) for t in TASKS)
MATRIX=frozenset((mode,task,kind) for mode,task in PATHS for kind in KINDS)
SHA=re.compile(r"^[a-f0-9]{64}$")
UUID=re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")

def need(value,message):
    if not value: raise AssertionError("BER admitted replay: "+message)

def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()

def normalized_command(command):
    need(isinstance(command,dict) and command.get("kind") in KINDS,"unsupported current command kind")
    c=dict(command);kind=c["kind"]
    required={"inspect_catalog":(),"inspect_offer":("resourceId",),"pay":("resourceId","offerId","offerReadActionId"),"retrieve":("payActionId",),"approve":("amountUnits","gasLimit"),"transfer":("amountUnits","recipient","gasLimit"),"wrap":("amountWei","gasLimit"),"unwrap":("amountWei","gasLimit"),"swap":("inputAssetId","outputAssetId","amountInUnits","amountOutMinimumUnits","recipient","gasLimit")}[kind]
    optional={"inspect_offer":("offerId",),"approve":("tokenAssetId",),"swap":("feeTier",)}.get(kind,())
    need(set(required)<=(set(c)-{"kind"}) and set(c)<={"kind",*required,*optional},"command field schema mismatch")
    if kind=="approve":c.setdefault("tokenAssetId","WETH")
    for key,value in c.items():
        if key in ("amountUnits","gasLimit","amountWei","amountInUnits","amountOutMinimumUnits"):
            need(isinstance(value,str) and re.fullmatch(r"(0|[1-9][0-9]{0,77})",value),"invalid bounded unsigned quantity")
        elif key=="recipient":
            need(isinstance(value,str) and re.fullmatch(r"0x[a-fA-F0-9]{40}",value),"invalid recipient")
            c[key]=value.lower()
        elif key in ("inputAssetId","outputAssetId","tokenAssetId"):need(value in ("WETH","USDC"),"invalid asset")
        elif key=="feeTier":need(type(value) is int and value in (500,3000),"invalid fee tier")
        elif key in ("resourceId","offerId"):need(isinstance(value,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",value),"invalid resource identity")
        elif key in ("offerReadActionId","payActionId"):need(isinstance(value,str) and re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}",value),"invalid original action reference")
    if kind=="swap":need(c["inputAssetId"]!=c["outputAssetId"],"swap assets must differ")
    return c

def verify_census(census,owner,root):
    need(census.get("schemaVersion")=="bts-admitted-action-census/v1" and census.get("classification")=="identity_and_evidence_census_not_effect_proof","census schema/authority mismatch")
    observer=owner.get("observer",{});need(owner.get("source")=="postgresql_observer" and observer.get("role")=="oid_observer" and observer.get("readOnly") is True and observer.get("databaseName"),"independent readonly owner snapshot absent")
    for key in ("binding","taskIndex","execution","closure"):need(owner.get(key)==census.get(key),"owner snapshot binding mismatch: "+key)
    binding=census["binding"];execution=census["execution"];closure=census["closure"];rows=owner.get("rows");entries=census.get("entries")
    need(all(UUID.fullmatch(str(binding.get(k,""))) for k in ("ownerId","agentId","runId")) and binding.get("taskId") in TASKS,"invalid bound identity")
    need(all(SHA.fullmatch(str(binding.get(k,""))) for k in ("manifestHash","caseHash","rubricHash")) and all(isinstance(binding.get(k),str) and binding[k] for k in ("releaseIdentity","caseId","environmentId")),"incomplete release binding")
    need(type(census.get("taskIndex")) is int and 0<=census["taskIndex"]<=11 and execution.get("environmentId")==binding["environmentId"],"invalid task/execution binding")
    need(all(UUID.fullmatch(str(execution.get(k,""))) for k in ("preparationId","leaseId","generationId")) and all(SHA.fullmatch(str(execution.get(k,""))) for k in ("environmentManifestHash","applicationSourceHash","executionIdentityHash","initialStateSha256")),"invalid immutable execution pins")
    need(UUID.fullmatch(str(closure.get("closureId",""))) and SHA.fullmatch(str(closure.get("payloadHash",""))) and closure.get("reason") in ("agent_finish","task_deadline","run_deadline"),"invalid closure identity")
    need(closure.get("operationId") is None or isinstance(closure["operationId"],str) and re.fullmatch(r"[A-Za-z0-9_-]{12,128}",closure["operationId"]),"invalid closure operation identity")
    cutoff=closure.get("actionCutoffSequence");need(type(cutoff) is int and 0<=cutoff<=256 and closure.get("reconciledActionSequence")==cutoff,"unreconciled or invalid cutoff")
    need(isinstance(rows,list) and isinstance(entries,list) and len(rows)==len(entries)==cutoff,"truncated or skipped action census")
    ids=set();ops=set();kinds=set()
    for sequence,(row,entry) in enumerate(zip(rows,entries),1):
        need(type(row.get("action_sequence")) in (str,int) and re.fullmatch(r"[1-9][0-9]*",str(row["action_sequence"])),"invalid original sequence")
        need(int(row["action_sequence"])==sequence and entry.get("actionSequence")==sequence,"noncontiguous sequence")
        need(row["id"] not in ids and row["operation_id"] not in ops,"duplicate original action/operation");ids.add(row["id"]);ops.add(row["operation_id"])
        need(UUID.fullmatch(row["id"]) and re.fullmatch(r"[A-Za-z0-9_-]{12,128}",row["operation_id"]) and SHA.fullmatch(row["payload_hash"]),"invalid original action identity")
        for k,v in (("run_id",binding["runId"]),("owner_id",binding["ownerId"]),("agent_id",binding["agentId"]),("task_id",binding["taskId"]),("environment_id",binding["environmentId"]),("task_index",census["taskIndex"])):need(row.get(k)==v,"foreign owner action scope")
        for suffix in ("revision","status","evidence_hash","evidence_path","transaction_hash"):need(row.get("history_"+suffix)==row.get("receipt_"+suffix if suffix in ("revision","status") else suffix),"receipt history mismatch")
        need(type(row["receipt_revision"]) is int and row["receipt_revision"]>=1 and row["receipt_status"] in ("observed","rejected_before_execution"),"unknown or invalid receipt cannot prove known effects")
        need(row.get("transaction_hash") is None or isinstance(row["transaction_hash"],str) and re.fullmatch(r"0x[a-f0-9]{64}",row["transaction_hash"]),"invalid transaction identity")
        command=row["command_json"];command=json.loads(command) if isinstance(command,str) else command;command=normalized_command(command)
        need(command["kind"]==row["action_kind"] and digest({"runId":binding["runId"],"taskIndex":census["taskIndex"],"command":command})==row["payload_hash"],"chosen command hash mismatch")
        ref={"path":row["evidence_path"],"sha256":row["evidence_hash"]};document=read_reference(root,ref)
        need(ref["path"].startswith("artifacts/runs/owner-identity-bef-task-coordinator/action/") and (root/ref["path"]).stat().st_size<=2*1024*1024,"action evidence outside bounded immutable namespace")
        expected={"schema":"bef-task-action-observation-v1","actionId":row["id"],"runId":binding["runId"],"taskIndex":census["taskIndex"],"actionSequence":str(sequence),"ownerOperationId":row["operation_id"],"actionKind":row["action_kind"],"commandSha256":row["payload_hash"],"environmentId":binding["environmentId"],"generationId":execution["generationId"],"manifestSha256":execution["environmentManifestHash"],"applicationSourceSha256":execution["applicationSourceHash"],"idempotencyKey":"task-action-"+row["id"],"status":row["receipt_status"]}
        need(all(document.get(k)==v for k,v in expected.items()),"action evidence lineage mismatch")
        need(document.get("transactionHash")==row["transaction_hash"],"transaction evidence mismatch")
        expected_entry={"actionId":row["id"],"actionSequence":sequence,"ownerOperationId":row["operation_id"],"actionKind":row["action_kind"],"command":command,"commandSha256":row["payload_hash"],"receiptRevision":row["receipt_revision"],"receiptStatus":row["receipt_status"],"transactionHash":row["transaction_hash"],"document":document}
        need(all(entry.get(k)==v for k,v in expected_entry.items()),"census entry differs from independently observed original")
        family="read" if command["kind"].startswith("inspect_") else "payment" if command["kind"] in ("pay","retrieve") else "chain"
        need(entry.get("family")==family and entry.get("actionEvidence",{}).get("path")==ref["path"] and entry["actionEvidence"].get("sha256")==ref["sha256"] and entry["actionEvidence"].get("boundary")=="actual_tool_http_x402_local_evm_application_store","family/ref identity mismatch")
        kinds.add(command["kind"])
    return {"count":len(entries),"kinds":sorted(kinds),"identityOnly":True}

def verify_matrix(cells,root):
    need(isinstance(cells,list),"fifteen-by-nine cells absent");seen=set();reports=[]
    for cell in cells:
        key=(cell.get("mode"),cell.get("taskId"),cell.get("kind"));need(key in MATRIX and key not in seen,"foreign/duplicate mode-task-kind cell");seen.add(key)
        census=read_reference(root,cell["censusRef"]);owner=read_reference(root,cell["ownerSnapshotRef"])
        need(census.get("binding",{}).get("taskId")==key[1] and owner.get("mode")==key[0],"matrix mode/task differs from actual owner snapshot")
        report=verify_census(census,owner,root);need(key[2] in report["kinds"],"required command kind missing from original rows");reports.append(report)
    need(seen==MATRIX,"missing fifteen-by-nine kind cells")
    return reports

def verify_admitted_learning_capture(reference,scenario_id,*,repository_root):
    root=Path(repository_root);capture=read_reference(root,reference)
    if capture.get("schemaVersion")=="ber-admitted-learning-full-capture/v1":
        from tests.bdd.adapters.ber_full_replay import verify_full_capture
        return verify_full_capture(reference,scenario_id,repository_root=root)
    need(capture.get("schemaVersion")=="ber-admitted-learning-identity-capture/v1","unsupported actual learning capture schema")
    sources=capture.get("sourceInputs",{});before=sources.get("before",{});need(before and before==sources.get("after"),"source cohort missing or changed")
    for path,expected in before.items():need(SHA.fullmatch(expected) and hashlib.sha256((root/path).read_bytes()).hexdigest()==expected,"current source drift")
    reports=verify_matrix(capture.get("cells"),root)
    # AICODE-NOTE: This partial raw schema has no independent economic or evaluator
    # boundary. Even all 135 strict identity cells can never set an effect gate passed.
    return {"scenarioId":scenario_id,"facts":{},"identityCells":len(reports),"fullScenarioAcceptance":"blocked","missingBoundaries":["independent_paid_and_chain_effect_replay","existing_rubric_known_unknown_and_negative_matrices","actual_restart_finance_handoff_proof","actual_native_training_ranked_ui_postgresql_acceptance"]}
