"""Independent, offline BER recovery-history replay.

Reconstructs immutable journals and their file bindings. It has no database, HTTP,
worker or command-dispatch client. Normal recovery and this reader have different
write authority. Native completion proof is a subset, never all of BER-SC-007.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

SHA = re.compile(r"^[a-f0-9]{64}$")
MAX_REFERENCE_BYTES = 32 * 1024 * 1024
MAX_UNKNOWN_MATRIX_BYTES = 128 * 1024 * 1024
UNKNOWN_DOCUMENT_SCHEMAS = {"ber-unknown-grading-capture/v1", "ber-unknown-grading-matrix/v1",
                            "ber-unknown-grading-matrix-assembly/v1"}
TASKS = ["S1", "S2", "S3", "S4", "M1", "M2", "M3", "M4", "H1", "H2", "H3", "U1"]
MISSING_007 = ["restart_at_cutoff", "restart_before_first_grade", "restart_at_successor_activation",
               "restart_at_completion_handoff", "crash_before_first_authorized_refund_commit", "duplicate_out_of_order_completion",
               "late_callback"]


def canonical(value: Any) -> bytes:
    # The captured task schema has integer/string values only. Reject floats rather
    # than silently choosing Python formatting in place of the original JS encoding.
    def check(v):
        if isinstance(v, float):
            raise AssertionError("floating-point history cannot be canonically replayed")
        if isinstance(v, dict):
            for x in v.values(): check(x)
        if isinstance(v, list):
            for x in v: check(x)
    check(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _require(condition: Any, reason: str):
    if not condition:
        raise AssertionError(reason)


def _one(rows: list, name: str) -> dict:
    _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), name + " needs exactly one row")
    return rows[0]


def _epoch(value: str) -> float:
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(t.tzinfo is not None, "timezone missing")
    return t.timestamp()


def read_reference(root: Path, reference: dict, *, json_body: bool = True, unknown_matrix_document: bool = False):
    """Resolve only bounded, hash-pinned files inside the declared repository copy."""
    text, expected = reference.get("path"), reference.get("sha256")
    _require(isinstance(text, str) and isinstance(expected, str) and SHA.fullmatch(expected), "invalid file reference")
    parts = PurePosixPath(text).parts
    _require(parts and not PurePosixPath(text).is_absolute() and "\\" not in text and ":" not in text
             and all(x not in {".", "..", ""} for x in text.split("/")), "unsafe file reference")
    base = root.resolve(strict=True)
    path = base.joinpath(*parts).resolve(strict=True)
    _require(base in path.parents and path.is_file(), "file reference escapes repository")
    _require(not unknown_matrix_document or json_body, "unknown matrix allowance requires a typed JSON document")
    limit = MAX_UNKNOWN_MATRIX_BYTES if unknown_matrix_document else MAX_REFERENCE_BYTES
    _require(path.stat().st_size <= limit, "file evidence exceeds bounded document size")
    data = path.read_bytes()
    _require(len(data) <= limit and hashlib.sha256(data).hexdigest() == expected, "file evidence hash mismatch")
    if not json_body:
        return data
    value = json.loads(data.decode("utf-8-sig"))
    if unknown_matrix_document:
        _require(isinstance(value, dict) and value.get("schemaVersion") in UNKNOWN_DOCUMENT_SCHEMAS,
                 "large document allowance is restricted to unknown matrix documents")
    from tests.bdd.adapters.beta_poc_delivery import _assert_secret_free
    _assert_secret_free(value, "replay_file")
    return value


def _references(value: Any, found: dict[str, str]):
    if isinstance(value, list):
        for x in value: _references(x, found)
    if isinstance(value, dict):
        if isinstance(value.get("path"), str) and SHA.fullmatch(str(value.get("sha256", ""))):
            path, sha = value["path"], value["sha256"]
            _require(path not in found or found[path] == sha, "contradictory evidence hashes")
            found[path] = sha
        for x in value.values(): _references(x, found)


def _index(rows, key, name):
    out = {}
    for row in rows:
        k = row[key]
        _require(k not in out, "duplicate " + name)
        out[k] = row
    return out


def _event(events, kind, index=None):
    selected = [e for e in events if e["event_type"] == kind and (index is None or e["payload_json"].get("taskIndex") == index)]
    return _one(selected, kind)


def _replay_run(packet, load):
    rows, sets = packet["rows"], packet["sets"]
    _require(set(rows) == set(sets), "raw row inventory differs from fingerprints")
    for name, values in rows.items():
        ordered = sorted(values, key=canonical)
        _require(sets[name] == {"count": len(values), "sha256": digest(ordered)}, "raw set hash mismatch: " + name)
    run = _one(rows["run"], "run")
    run_id, mode = run["id"], run["mode"]
    _require(run_id == packet["runId"] and run["status"] == "completed" and run["terminal_reason"] is None
             and run["cancellation_reason"] is None and run["cancellation_requested_at"] is None, "run is not normally completed")
    order = ["S1", "M1", "H1"] if mode == "training" else TASKS
    _require(mode in {"training", "ranked"} and run["task_ids"] == order, "native task selection differs")
    release_row = _one(rows["release"], "release")
    release = release_row["sealed_manifest"]
    _require(release["manifestHash"] == release_row["manifest_hash"] == run["manifest_hash"]
             and digest({k:v for k,v in release.items() if k != "manifestHash"}) == run["manifest_hash"], "release manifest hash mismatch")
    for json_key, sql_key in [("releaseIdentity", "release_identity"), ("benchmarkVersion", "benchmark_version"),
                              ("benchmarkHash", "benchmark_hash"), ("policyHash", "policy_hash")]:
        _require(release[json_key] == run[sql_key] == release_row[sql_key], "release identity mismatch")
    tasks = sorted(rows["tasks"], key=lambda x:x["task_index"])
    _require([t["task_id"] for t in tasks] == order and [t["task_index"] for t in tasks] == list(range(len(order))), "task row order mismatch")
    evaluations = _index(rows["evaluations"], "task_index", "evaluation")
    bundles = _index(rows["bundles"], "task_index", "bundle")
    closures = _index(rows["closures"], "id", "closure")
    bindings = _index(rows["bindings"], "task_index", "binding")
    preparations = _index(rows["preparations"], "task_index", "preparation")
    leases = _index(rows["leases"], "preparation_id", "lease")
    receipts = _index(rows["receipts"], "action_id", "receipt")
    outboxes = _index(rows["outboxes"], "action_id", "outbox")
    actions = _index(rows["actions"], "id", "action")
    _require(len(evaluations) == len(bundles) == len(closures) == len(preparations) == len(leases) == len(tasks), "task proof rows incomplete")
    _require(set(receipts) == set(outboxes) == set(actions), "action/receipt/outbox identity set differs")
    events = sorted(rows["events"], key=lambda x:x["sequence"])
    _require([e["sequence"] for e in events] == list(range(1, len(events)+1)), "event sequence is missing, duplicate or reordered")
    for e in events:
        _require(e["run_id"] == run_id and digest(e["payload_json"]) == e["payload_hash"], "event payload hash mismatch")
    _event(events, "run.started")
    proofs = []
    for index, task in enumerate(tasks):
        _require(task["run_id"] == run_id and task["closure_status"] == "closed" and task["finished_at"], "task not terminal and closed")
        evaluation, bundle, prep, binding = evaluations[index], bundles[index], preparations[index], bindings[index]
        closure, lease = closures[task["closure_id"]], leases[prep["preparation_id"]]
        case = _one([c for c in release["cases"][mode] if c["taskId"] == task["task_id"]], "task case")
        for record in [evaluation, bundle, prep, binding]:
            _require(record["run_id"] == run_id and record["task_index"] == index, "foreign task proof")
        _require(evaluation["task_id"] == task["task_id"] and evaluation["closure_id"] == task["closure_id"]
                 and evaluation["manifest_hash"] == run["manifest_hash"] and evaluation["release_identity"] == run["release_identity"]
                 and evaluation["case_hash"] == case["caseHash"] and evaluation["rubric_hash"] == case["rubricHash"], "evaluation identity mismatch")
        inp, result = evaluation["input_json"], evaluation["result_json"]
        _require(digest(inp) == evaluation["input_hash"] and digest(result) == evaluation["result_hash"], "evaluation input/result hash mismatch")
        _require(inp["release"] == release and inp["taskCase"] == case, "evaluation case/release mismatch")
        _require(result["taskId"] == task["task_id"] and result["status"] == "known" and result["unknownReasons"] == []
                 and result["outcome"] in {"passed", "partial", "failed"}, "unknown or invalid result cannot complete")
        n, d = int(result["credit"]["numerator"]), int(result["credit"]["denominator"])
        _require(d > 0 and 0 <= n <= d and ((result["outcome"] == "passed" and n == d) or
                 (result["outcome"] == "partial" and 0 < n < d) or (result["outcome"] == "failed" and n == 0)), "result credit inconsistent")
        _require(task["status"] == ("failed" if result["outcome"] == "failed" else "completed"), "task status differs from result")
        cutoff = int(task["action_cutoff_sequence"])
        _require(cutoff == int(task["accepted_action_sequence"]) == int(task["reconciled_action_sequence"])
                 and closure["run_id"] == run_id and closure["task_index"] == index
                 and int(closure["action_cutoff_sequence"]) == cutoff
                 and closure["payload_hash"] == task["closure_payload_hash"]
                 and closure["reason"] == task["closure_reason"] and closure["operation_id"] == task["closure_operation_id"], "closure cutoff binding mismatch")
        expected_closure_hash = digest({"action":"task_finish", "runId":run_id, "taskIndex":index, "answer":closure["answer_json"]}) if closure["reason"] == "agent_finish" else digest({"runId":run_id,"taskIndex":index,"reason":closure["reason"]})
        _require(expected_closure_hash == closure["payload_hash"], "closure payload hash mismatch")
        bj = bundle["bundle_json"]
        _require(digest(bj) == bundle["bundle_hash"] and bj["observations"] == inp["observations"], "bundle/observation hash mismatch")
        for key, expected in {"runId":run_id,"ownerId":run["owner_id"],"agentId":run["agent_id"],"taskId":task["task_id"],"releaseIdentity":run["release_identity"],"manifestHash":run["manifest_hash"],"caseHash":case["caseHash"],"rubricHash":case["rubricHash"]}.items():
            _require(bj["binding"].get(key) == expected and inp["run"].get(key) == expected, "observation identity mismatch")
        _require(bj["closure"] == {"closureId":closure["id"],"operationId":closure["operation_id"],"payloadHash":closure["payload_hash"],"reason":closure["reason"],"actionCutoffSequence":cutoff,"reconciledActionSequence":cutoff}, "bundle closure mismatch")
        _require(inp["observations"]["binding"] == bj["binding"] and bj["cutoff"]["status"] == "authoritative"
                 and inp["run"]["cutoffStatus"] == "authoritative"
                 and inp["run"]["acceptedActionCutoffSequence"] == cutoff
                 and inp["run"]["reconciledThroughActionSequence"] == cutoff
                 and inp["run"]["cutoffEvidence"] == bj["cutoff"]["evidence"] == bundle["cutoff_evidence"], "evaluation observation cutoff differs")
        ex, fence = bj["execution"], lease["fence_evidence"]
        _require(lease["state"] == "fenced" and fence["confirmed"] is True and ex["preparationId"] == prep["preparation_id"] == fence["preparationId"]
                 and ex["leaseId"] == prep["lease_id"] == lease["lease_id"] == fence["leaseId"]
                 and ex["generationId"] == binding["generation_id"] == fence["generationId"]
                 and prep["environment_id"] == binding["env_id"] == fence["environmentId"] == bundle["environment_id"], "original generation fence mismatch")
        _require(prep["release_identity"] == run["release_identity"] and prep["manifest_hash"] == run["manifest_hash"]
                 and prep["case_hash"] == case["caseHash"] and prep["execution_identity_hash"] == case["executionIdentityHash"]
                 and prep["application_source_hash"] == binding["application_source_hash"] == ex["applicationSourceHash"] == release["executionIdentity"]["x402ServiceSha256"]
                 and prep["environment_manifest_sha256"] == binding["manifest_hash"] == ex["environmentManifestHash"] == release["executionIdentity"]["environmentManifestSha256"], "preparation/application source pins differ")
        fp = load(fence["evidence"])
        _require(fp["preparationId"] == prep["preparation_id"] and fp["environmentId"] == prep["environment_id"]
                 and fp["evidence"]["fenceConfirmed"] is True
                 and fp["evidence"]["actualBefGenerationId"] == ex["generationId"] == fp["evidence"]["expectedOwnerGenerationId"]
                 and fp["evidence"]["after"]["status"] == "fenced", "raw fence proof differs")
        task_actions = sorted([a for a in actions.values() if a["task_index"] == index], key=lambda a:a["action_sequence"])
        _require([int(a["action_sequence"]) for a in task_actions] == list(range(1, cutoff+1)), "admitted action cutoff incomplete")
        cutoff_event = _event(events,"task.cutoff.established",index)
        _require(cutoff_event["payload_json"] == {"closureId":closure["id"],"taskIndex":index,"taskId":task["task_id"],"reason":closure["reason"],"actionCutoffSequence":str(cutoff)}, "cutoff event differs")
        last_reconciliation_sequence = 0
        for a in task_actions:
            _require(a["run_id"] == run_id and a["owner_id"] == run["owner_id"] and a["agent_id"] == run["agent_id"]
                     and a["task_id"] == task["task_id"] and a["environment_id"] == prep["environment_id"], "action ownership differs")
            _require(digest({"runId":run_id,"taskIndex":index,"command":a["command_json"]}) == a["payload_hash"], "action payload hash differs")
            receipt, outbox = receipts[a["id"]], outboxes[a["id"]]
            _require(receipt["receipt_status"] in {"observed", "rejected_before_execution"} and outbox["status"] == "delivered", "action receipt unresolved")
            action_packet = load({"path":receipt["evidence_path"],"sha256":receipt["evidence_hash"]})
            for key, expected in {"actionId":a["id"],"runId":run_id,"taskIndex":index,"ownerOperationId":a["operation_id"],"generationId":ex["generationId"],"environmentId":prep["environment_id"],"commandSha256":a["payload_hash"]}.items():
                _require(action_packet.get(key) == expected, "raw receipt identity differs")
            _require(action_packet["actionSequence"] == str(a["action_sequence"]), "raw receipt sequence differs")
            if receipt["tool_response_json"] is not None:
                _require(digest(receipt["tool_response_json"]) == receipt["tool_response_hash"], "tool response hash differs")
            _require(any(r["action_id"] == a["id"] and r["evidence_hash"] == receipt["evidence_hash"]
                         and r["receipt_status"] == receipt["receipt_status"] for r in rows["reconciliations"]), "receipt reconciliation journal missing")
            admitted = _one([e for e in events if e["event_type"] == "task.action.admitted" and e["payload_json"].get("actionId") == a["id"]], "action admitted event")
            _require(admitted["source"] == "agent" and admitted["sequence"] < cutoff_event["sequence"]
                     and admitted["payload_json"] == {"actionId":a["id"],"taskIndex":index,"taskId":task["task_id"],"actionSequence":str(a["action_sequence"]),"operationId":a["operation_id"],"actionKind":a["action_kind"],"payloadHash":a["payload_hash"]}, "admission event binding/order differs")
            reconciled = _one([e for e in events if e["event_type"] == "task.action.reconciled" and e["payload_json"].get("actionId") == a["id"] and e["payload_json"].get("receiptRevision") == receipt["receipt_revision"]], "final reconciliation event")
            _require(reconciled["source"] == "executor" and reconciled["sequence"] > admitted["sequence"]
                     and reconciled["payload_json"]["evidenceHash"] == receipt["evidence_hash"]
                     and reconciled["payload_json"]["receiptStatus"] == receipt["receipt_status"], "reconciliation event binding/order differs")
            last_reconciliation_sequence = max(last_reconciliation_sequence,reconciled["sequence"])
        evaluated = _event(events, "task.evaluated", index)
        _require(evaluated["payload_json"]["inputHash"] == evaluation["input_hash"] and evaluated["payload_json"]["resultHash"] == evaluation["result_hash"]
                 and evaluated["payload_json"]["closureId"] == closure["id"] and evaluated["sequence"] > max(cutoff_event["sequence"],last_reconciliation_sequence), "evaluated event binding/order differs")
        proofs.append({"taskIndex":index,"taskId":task["task_id"],"closureId":closure["id"],"inputHash":evaluation["input_hash"],"resultHash":evaluation["result_hash"],"preparationId":prep["preparation_id"],"leaseId":prep["lease_id"],"generationId":ex["generationId"],"fenceEvidenceHash":fence["evidence"]["sha256"]})
    for index,proof in enumerate(proofs[:-1]):
        terminal = _event(events,"task.terminalized",index)
        _require(terminal["source"] == "coordinator" and all(terminal["payload_json"].get(k) == v for k,v in proof.items())
                 and terminal["sequence"] > _event(events,"task.evaluated",index)["sequence"], "predecessor terminal event differs")
        successor = _one([e for e in events if e["event_type"] == "task.activated" and e["payload_json"].get("toTaskIndex") == index+1], "successor activated event")
        payload = successor["payload_json"]
        _require(successor["source"] == "coordinator" and successor["sequence"] > terminal["sequence"]
                 and payload["fromTaskIndex"] == index and payload["toTaskId"] == order[index+1]
                 and all(payload["predecessorReceipt"].get(k) == proof[k] for k in ("closureId","inputHash","resultHash","preparationId","leaseId","generationId","fenceEvidenceHash"))
                 and payload["binding"]["generationId"] == proofs[index+1]["generationId"]
                 and _epoch(payload["activatedAt"]) == _epoch(tasks[index+1]["started_at"]), "successor activation proof differs")
    completed = _event(events, "run.completed")
    _require(completed["source"] == "coordinator" and completed["payload_json"]["tasks"] == proofs
             and _epoch(completed["payload_json"]["finishedAt"]) == _epoch(run["finished_at"]), "completion event proof differs")
    _require(len(rows["slots"]) == 0 and _one(rows["claims"], "claim")["status"] == "released", "resources not released")
    ledger = rows["ledger"]
    _require(len(ledger) == 1 and ledger[0]["entry_type"] == "debit" and ledger[0]["source_kind"] == "tester_bonus"
             and int(ledger[0]["amount_units"]) == int(run["quote_price_units"]), "charge not once-only bonus or unauthorized refund")
    if mode == "ranked":
        handoff, verified, version = (_one(rows[k], k) for k in ("handoffs", "results", "version"))
        hj, aggregate = handoff["handoff_json"], verified["aggregate_json"]
        _require(digest(hj) == handoff["handoff_hash"] == _event(events, "run.ranked_eligible")["payload_hash"]
                 and hj["completionEventHash"] == completed["payload_hash"] == handoff["completion_event_hash"], "ranked handoff hash mismatch")
        _require(digest({k:v for k,v in aggregate.items() if k != "aggregateHash"}) == aggregate["aggregateHash"] == verified["aggregate_hash"] == handoff["aggregate_hash"], "ranked aggregate hash mismatch")
        _require(digest(version["snapshot_json"]) == version["snapshot_hash"] == verified["version_snapshot_hash"] == handoff["version_snapshot_hash"]
                 and version["snapshot_json"] == verified["version_snapshot_json"], "version snapshot mismatch")
        _require(len(aggregate["taskProofs"]) == len(proofs), "ranked proof count mismatch")
        for i,p in enumerate(aggregate["taskProofs"]):
            _require(all(p[k] == proofs[i][k] for k in ("taskIndex","taskId","inputHash","resultHash","fenceEvidenceHash"))
                     and p["result"] == evaluations[i]["result_json"], "ranked aggregate task proof differs")
    else:
        _require(not rows["handoffs"] and not rows["results"], "training gained ranked publication")
    return {"runId":run_id,"mode":mode,"tasks":len(tasks),"actions":len(actions),"evaluations":len(evaluations),"fences":len(leases),
            "completionEvents":1,"bonusDebits":1,"handoffs":len(rows["handoffs"]),"verifiedResults":len(rows["results"]),"slots":0}


def verify_native_recovery_history(reference: dict, *, repository_root: Path | None = None, required_modes: list[str] | None = None) -> dict:
    root = repository_root or Path(__file__).resolve().parents[3]
    capture = read_reference(root, reference)
    _require(capture.get("schemaVersion") == "ber-independent-replay-raw-history/v1" and capture.get("mode") == "history", "unsupported history capture")
    observer = capture["observer"]
    _require(observer == {"role":"oid_observer","read_only":"on","isolation":"repeatable read","database":capture["databaseName"]}, "observer not independently read-only")
    _require(capture["sourceHashes"] == capture["sourceHashesAfter"] and capture["sourceHashes"], "source inventory changed")
    for path, sha in capture["sourceHashes"].items(): read_reference(root,{"path":path,"sha256":sha},json_body=False)
    expected = {}
    for run in capture["runs"]:
        _references(run["rows"], expected)
        for receipt in run["rows"]["receipts"]:
            p,h = receipt["evidence_path"],receipt["evidence_hash"]
            _require(p not in expected or expected[p] == h, "contradictory receipt evidence")
            expected[p] = h
    _require(len(capture["artifacts"]) == len(expected) and {x["path"]:x["sha256"] for x in capture["artifacts"]} == expected, "artifact reference inventory incomplete")
    cache = {}
    for artifact in capture["artifacts"]:
        data = read_reference(root,artifact,json_body=False)
        _require(len(data) == artifact["sizeBytes"], "artifact byte size differs")
        if artifact["path"].endswith(".json"):
            value = json.loads(data.decode("utf-8-sig"))
            from tests.bdd.adapters.beta_poc_delivery import _assert_secret_free
            _assert_secret_free(value,"raw_artifact")
            cache[(artifact["path"],artifact["sha256"])] = value
    def load(ref):
        key = (ref["path"],ref["sha256"])
        _require(key in cache, "unindexed raw proof")
        return cache[key]
    runs = [_replay_run(p,load) for p in capture["runs"]]
    _require(sorted(r["mode"] for r in runs) == sorted(required_modes or ["ranked","training"]), "required completed native history modes differ")
    return {"schemaVersion":"ber-independent-history-replay/v1","status":"verified_subset","fullScenarioAcceptance":"blocked",
            "boundary":"offline_raw_journal_and_hash_pinned_file_reconstruction","runs":runs,"artifactCount":len(expected),
            "facts":{"source_and_artifact_hashes":True,"task_action_closure_evaluation_chain":True,"completion_handoff":True,
                     "exact_resource_release":True},"missingVariants":MISSING_007.copy()}


def verify_database_window(before_ref: dict, after_ref: dict, report: dict, *, repository_root: Path | None = None) -> dict:
    root = repository_root or Path(__file__).resolve().parents[3]
    before, after = (read_reference(root,ref) for ref in (before_ref,after_ref))
    for value in (before,after):
        _require(value["schemaVersion"] == "ber-independent-replay-raw-history/v1" and value["mode"] == "fingerprint"
                 and value["observer"]["role"] == "oid_observer" and value["observer"]["read_only"] == "on", "database fingerprint observer invalid")
    _require(before["databaseName"] == after["databaseName"] and [(r["runId"],r["sets"]) for r in before["runs"]] == [(r["runId"],r["sets"]) for r in after["runs"]], "database rows changed across replay")
    original = read_reference(root,report["capture"])
    _require(before["databaseName"] == original["databaseName"]
             and [(r["runId"],r["sets"]) for r in before["runs"]] == [(r["runId"],r["sets"]) for r in original["runs"]], "database window does not bind the replayed raw history")
    _require(before["sourceHashes"] == before["sourceHashesAfter"] == after["sourceHashes"] == after["sourceHashesAfter"] == original["sourceHashes"], "database observer source identity changed")
    _require(_epoch(before["observedAt"]) <= _epoch(report["startedAt"]) <= _epoch(report["finishedAt"]) <= _epoch(after["observedAt"]), "database fingerprints do not surround replay")
    _require(report["schemaVersion"] == "ber-independent-two-replay-report/v1" and len(report["passes"]) == 2,
             "two actual replay outputs missing")
    passes = report["passes"]
    expected = verify_native_recovery_history(report["capture"],repository_root=root,required_modes=report.get("requiredModes"))
    _require(all(p["output"] == expected and p["outputSha256"] == digest(expected) for p in passes)
             and _epoch(report["startedAt"]) <= _epoch(passes[0]["startedAt"]) <= _epoch(passes[0]["finishedAt"])
             <= _epoch(passes[1]["startedAt"]) <= _epoch(passes[1]["finishedAt"]) <= _epoch(report["finishedAt"]), "replay output or causal order differs")
    _require(report["inputFingerprints"] == report["inputFingerprintsAfter"] and report["checkedFiles"] == len(report["inputFingerprints"]), "replay filesystem inventories differ")
    for path,sha in report["inputFingerprints"].items(): read_reference(root,{"path":path,"sha256":sha},json_body=False)
    _require(report["readerSourceSha256"] == report["inputFingerprints"]["tests/bdd/adapters/ber_recovery_replay.py"]
             and report["runnerSourceSha256"] == report["inputFingerprints"]["tools/replay_ber_recovery.py"], "replay reader/runner source binding differs")
    return {"databaseScopedRowsUnchanged":True,"readonlyObserver":True,"replayPasses":2,"fullScenarioAcceptance":"blocked"}


def verify_matrix(repository_root: Path, capture_refs: dict[str, dict]) -> dict:
    """Root integration entrypoint: returns only derived facts, with absent variants explicit."""
    facts, missing, observations = {}, MISSING_007.copy(), {}
    if "nativeHistory" in capture_refs:
        result = verify_native_recovery_history(capture_refs["nativeHistory"],repository_root=repository_root)
        facts.update(result["facts"]); observations["nativeHistory"] = result
    if "replayReport" in capture_refs and "databaseBefore" in capture_refs and "databaseAfter" in capture_refs:
        report = read_reference(repository_root,capture_refs["replayReport"])
        observations["readonlyWindow"] = verify_database_window(capture_refs["databaseBefore"],capture_refs["databaseAfter"],report,repository_root=repository_root)
        facts["readonly_replay_zero_business_writes"] = True
        # Independently exercise missing/tampered *copies* again at replay time;
        # the producer's negative-result flags are not accepted as observations.
        from tools.replay_ber_recovery import run as replay_live
        live = replay_live(report["capture"],repository_root=repository_root,required_modes=report.get("requiredModes"))
        _require(set(live["negativeCopies"]) == {"missing_raw_artifact","tampered_raw_artifact","wrong_generation_with_recomputed_hashes"}
                 and all(v["status"] == "rejected" for v in live["negativeCopies"].values()), "live copied-artifact negatives incomplete")
        facts["missing_or_tampered_artifact"] = True
        observations["liveNegativeReplay"] = {"negativeCopies":live["negativeCopies"],"readerSourceSha256":live["readerSourceSha256"]}
    if "completedCallbacks" in capture_refs:
        callbacks = verify_completed_callbacks(capture_refs["completedCallbacks"],repository_root=repository_root)
        observations["completedCallbacks"] = callbacks
        facts.update(callbacks["facts"])
        missing = [name for name in missing if name not in {"duplicate_out_of_order_completion","late_callback"}]
    if "faultCore" in capture_refs:
        core=verify_fault_core(capture_refs["faultCore"],repository_root=repository_root)
        observations["faultCore"]=core
        outer=read_reference(repository_root,capture_refs["faultCore"])
        exhausted=outer["result"]["cases"]["recoveryDeadlineExhaustion"]
        if exhausted["recovery"].get("refundCrash"):
            refund=verify_first_refund_crash(exhausted["recovery"]["refundCrash"],database=core["databaseName"],action=exhausted["action"],binding=exhausted["binding"],repository_root=repository_root)
            observations["firstRefundCrash"]=refund; facts.update(refund["facts"])
            missing=[name for name in missing if refund["facts"].get(name) is not True]
    if "unknownMatrix" in capture_refs:
        # Validate the supplied full capture even when it only contains a subset.
        observations["unknownMatrix"]=verify_unknown_matrix(capture_refs["unknownMatrix"],repository_root=repository_root)
        selected={(item["captureId"],item["caseName"]) for item in observations["unknownMatrix"]["selectedObservations"]}
        for outer,matrix,database in _unknown_capture_parts(capture_refs["unknownMatrix"],repository_root):
            for case in matrix.get("caseResults",[]):
                if (outer["captureId"],case["name"]) not in selected: continue
                for key,reader in (("pendingTransition",verify_pending_transition),("completedCallbacks",verify_completed_callbacks),("completionHandoff",verify_completion_handoff)):
                    if case.get(key,{}).get("evidence"):
                        result=reader(case[key]["evidence"],repository_root=repository_root)
                        _require(result["runId"] == case["runId"],"nested transition/callback belongs to another run")
                        observations[case["name"]+"_"+key]=result; facts.update(result["facts"])
                        missing=[name for name in missing if result["facts"].get(name) is not True]
    if "h1CutoffMatrix" in capture_refs:
        from tests.bdd.adapters.ber_h1_replay import verify_h1_matrix
        h1=verify_h1_matrix(capture_refs["h1CutoffMatrix"],repository_root=repository_root)
        observations["h1CutoffMatrix"]=h1
        if h1.get("restart_at_cutoff") is True:
            facts["restart_at_cutoff"]=True; missing=[n for n in missing if n != "restart_at_cutoff"]
    if "freshBaseline" in capture_refs:
        baseline=verify_fresh_baseline(capture_refs["freshBaseline"],repository_root=repository_root)
        observations["freshBaseline"]=baseline
        for history in baseline["histories"]: facts.update(history["facts"])
        facts["readonly_replay_zero_business_writes"]=True
        facts["missing_or_tampered_artifact"]=True
    else:
        missing.append("fresh_current_source_training3_and_full12_baseline")
    if facts.get("readonly_replay_zero_business_writes") is True and facts.get("exact_resource_release") is True:
        facts["before_after_ledger_and_slots"]=True
    if facts.get("duplicate_out_of_order_completion") is True and facts.get("completion_handoff") is True:
        facts["idempotent_authorized_recovery_completion"]=True
    transitions=("restart_at_cutoff","restart_before_first_grade","restart_at_successor_activation","restart_at_completion_handoff")
    if all(facts.get(name) is True for name in transitions): facts["restart_each_transition"]=True
    if all(facts.get(name) is True for name in ("restart_each_transition","crash_before_first_authorized_refund_commit","readonly_replay_zero_business_writes")):
        facts["crash_recovery_once_only_write_vs_readonly_replay_zero_write"]=True
    required_facts={"source_and_artifact_hashes","task_action_closure_evaluation_chain","completion_handoff","before_after_ledger_and_slots",
                    "crash_recovery_once_only_write_vs_readonly_replay_zero_write","duplicate_out_of_order_completion","missing_or_tampered_artifact",
                    "restart_each_transition","late_callback","crash_before_first_authorized_refund_commit","idempotent_authorized_recovery_completion",
                    "readonly_replay_zero_business_writes","exact_resource_release"}
    complete=not missing and all(facts.get(k) is True for k in required_facts)
    return {"facts":facts,"missingVariants":missing,"observations":observations,"fullScenarioAcceptance":"passed" if complete else "blocked"}


def _training_source_inventory(value: list, root: Path) -> dict:
    """Normalize the runner's declared source array without silently losing duplicates."""
    _require(isinstance(value,list) and value,"fresh Training3 source array missing")
    from tests.bdd.adapters.beta_poc_recovery_verifier import _REPLAY_READER_PATHS
    inventory={}
    for entry in value:
        _require(isinstance(entry,dict) and set(entry) == {"path","sha256","bytes"}
                 and isinstance(entry["path"],str) and entry["path"] not in inventory
                 and isinstance(entry["sha256"],str) and SHA.fullmatch(entry["sha256"])
                 and type(entry["bytes"]) is int and entry["bytes"] >= 0,"fresh Training3 source entry malformed or duplicated")
        if entry["path"] not in _REPLAY_READER_PATHS:
            data=read_reference(root,entry,json_body=False)
            _require(len(data) == entry["bytes"],"fresh Training3 source byte count differs")
        inventory[entry["path"]]=entry["sha256"]
    return inventory


def verify_fresh_baseline(reference: dict, *, repository_root: Path | None = None) -> dict:
    """Join fresh source-qualified browser captures to full independently replayed rows."""
    root=repository_root or Path(__file__).resolve().parents[3]
    manifest=read_reference(root,reference)
    _require(manifest["schemaVersion"] == "ber-fresh-current-source-baseline/v1","fresh baseline manifest invalid")
    training=read_reference(root,manifest["trainingCapture"])
    _require(training["schemaVersion"] == "genuine-training-sequence-owner-run-capture/v1" and training["taskIds"] == ["S1","M1","H1"]
             and training["mode"] == "training","fresh Training3 capture selection differs")
    provenance=training["provenance"]; isolation=provenance["databaseIsolation"]
    _require(isolation["createdForCapture"] is True and isolation["databaseName"] == "oid_acceptance_"+training["captureId"].replace("-","")
             and provenance["sourceStableDuringRun"] is True and provenance["inputHashesBefore"] == provenance["inputHashesAfter"],"fresh Training3 source/isolation invalid")
    training_sources=_training_source_inventory(provenance["inputHashesBefore"],root)
    launch=training["launchIntent"]; run_id=training["run"]["runId"]
    _require(launch["browserHttpStatus"] in {200,201} and launch["database"]["id"] == launch["intentId"]
             and launch["database"]["status"] == "pending" and launch["database"]["run_id"] is None
             and launch["operationId"] == training["run"]["createIntentOperationId"]
             and any(s["name"] == "owner_run_intent_ui_and_readonly_database" and s["status"] == "verified" and s["intentId"] == launch["intentId"] for s in training["stages"]),"fresh Training3 lacks browser to durable launch proof")
    train_history=verify_native_recovery_history(manifest["trainingHistory"],repository_root=root,required_modes=["training"])
    raw_training=read_reference(root,manifest["trainingHistory"])
    _require(raw_training["databaseName"] == isolation["databaseName"] and train_history["runs"][0]["runId"] == run_id,"fresh Training3 history belongs to another capture")
    _,selected,_=_unknown_validated_observations(manifest["rankedCapture"],root)
    candidates=[item for item in selected if item[3]["name"] == manifest["rankedCase"]]
    outer,matrix,database,case,result=_one_tuple(candidates,"fresh full12 recovery case")
    ranked_sources=outer["provenance"]["inputHashesBefore"]
    allowed_extra={"openspec/changes/benchmark-execution-reliability/bdd-design.md",
                   "tests/bdd/changes/benchmark-execution-reliability/harness-contracts.json",
                   "tools/capture_ber_replay_history.mjs","tools/ber_completed_callbacks.mjs",
                   "tools/ber_pending_transition_interruption.mjs","tools/ber_completion_handoff_interruption.mjs"}
    _require(training_sources and set(training_sources).issubset(ranked_sources)
             and all(ranked_sources[p] == sha for p,sha in training_sources.items())
             and all(p in allowed_extra or p.startswith("openspec/changes/benchmark-execution-reliability/specs/") for p in set(ranked_sources)-set(training_sources)),
             "fresh Training3/Full12 product sources differ or undeclared source roots were omitted")
    _require(result["complete"] and case["name"] in {"missing_recover","conflicting_recover"},"fresh Full12 is incomplete")
    ranked_history=verify_native_recovery_history(manifest["rankedHistory"],repository_root=root,required_modes=["ranked"])
    raw_ranked=read_reference(root,manifest["rankedHistory"])
    _require(raw_ranked["databaseName"] == database and ranked_history["runs"][0]["runId"] == case["runId"],"fresh Full12 history belongs to another capture")
    replay_proofs={}
    for mode,key in (("training","trainingHistory"),("ranked","rankedHistory")):
        window=manifest[mode+"Replay"]
        report=read_reference(root,window["report"])
        _require(report["capture"] == manifest[key] and report["requiredModes"] == [mode],"fresh replay does not bind the fresh run")
        replay_proofs[mode]=verify_database_window(window["before"],window["after"],report,repository_root=root)
        from tools.replay_ber_recovery import run as replay_live
        live=replay_live(manifest[key],repository_root=root,required_modes=[mode])
        _require(set(live["negativeCopies"]) == {"missing_raw_artifact","tampered_raw_artifact","wrong_generation_with_recomputed_hashes"}
                 and all(v["status"] == "rejected" for v in live["negativeCopies"].values()),"fresh replay copied negative incomplete")
    return {"status":"verified","trainingRunId":run_id,"rankedRunId":case["runId"],"boundary":"fresh_current_source_browser_worker_full_raw_history","histories":[train_history,ranked_history],"replayWindows":replay_proofs}


def _one_tuple(rows: list, name: str):
    _require(len(rows) == 1,name+" needs exactly one item")
    return rows[0]


def verify_completed_callbacks(reference: dict, *, repository_root: Path | None = None) -> dict:
    """Actual private callback integration, separate from read-only artifact replay."""
    root = repository_root or Path(__file__).resolve().parents[3]
    capture = read_reference(root,reference)
    _require(capture["schemaVersion"] == "ber-private-completed-callback-probes/v1"
             and capture["boundary"] == "isolated_completed_ranked_private_worker_services_actual_postgres_no_executor_dispatch"
             and re.fullmatch(r"oid_acceptance_[a-f0-9]{32}",capture["databaseName"]), "callback probe boundary differs")
    _require(capture["sourceBefore"] == capture["sourceAfter"] and capture["sourceBefore"], "callback source changed")
    for path,sha in capture["sourceBefore"].items(): read_reference(root,{"path":path,"sha256":sha},json_body=False)
    before = capture["before"]
    _require(before["identity"]["role"] == "oid_observer" and before["identity"]["read_only"] == "on"
             and before["identity"]["database_name"] == capture["databaseName"], "callback observer is not independently read-only")
    _require(set(before["rows"]) == set(before["sets"]), "callback raw inventory incomplete")
    for name,rows in before["rows"].items():
        _require(before["sets"][name] == {"count":len(rows),"sha256":digest(sorted(rows,key=canonical))}, "callback raw fingerprint mismatch")
    rows,target = before["rows"],capture["target"]
    run = _one(rows["run"],"callback run")
    _require(run["id"] == target["runId"] and run["owner_id"] == target["ownerId"] and run["agent_id"] == target["agentId"]
             and run["status"] == "completed" and run["mode"] == "ranked" and run["task_ids"] == TASKS
             and run["terminal_reason"] is None and run["cancellation_reason"] is None, "callback target is not a normally completed full Ranked")
    _require(len(rows["tasks"]) == len(rows["evaluations"]) == len(rows["leases"]) == 12
             and before["sets"]["slots"]["count"] == 0 and _one(rows["claims"],"callback claim")["status"] == "released"
             and len(rows["handoffs"]) == len(rows["results"]) == 1, "callback baseline completion/resources incomplete")
    for evaluation in rows["evaluations"]:
        _require(digest(evaluation["input_json"]) == evaluation["input_hash"] and digest(evaluation["result_json"]) == evaluation["result_hash"]
                 and evaluation["result_json"]["status"] == "known", "callback baseline grade invalid")
    for event in rows["events"]:
        _require(digest(event["payload_json"]) == event["payload_hash"], "callback baseline event hash invalid")
    _event(rows["events"],"run.completed");_event(rows["events"],"run.ranked_eligible")
    _require(len(rows["ledger"]) == 1 and rows["ledger"][0]["entry_type"] == "debit" and rows["ledger"][0]["source_kind"] == "tester_bonus", "callback baseline charge/refund differs")
    expected_names = ["duplicate_completion_1","duplicate_completion_2","out_of_order_terminal_callback_10",
                      "out_of_order_terminal_callback_0","out_of_order_terminal_callback_10","late_successor_callback_10","late_successor_callback_0"]
    _require([p["name"] for p in capture["probes"]] == expected_names, "callback variant order/inventory differs")
    tasks = _index(rows["tasks"],"task_index","callback task")
    for index,probe in enumerate(capture["probes"]):
        after = probe["after"]
        _require(after["identity"]["role"] == "oid_observer" and after["identity"]["read_only"] == "on"
                 and after["identity"]["database_name"] == capture["databaseName"]
                 and after["sets"] == before["sets"], "callback rewrote a business row")
        _require(probe["request"]["runId"] == run["id"] and _epoch(probe["startedAt"]) <= _epoch(probe["finishedAt"]), "callback request/time differs")
        response = probe["response"]
        if index < 2:
            _require(probe["error"] is None and response == {"runId":run["id"],"status":"completed","finishedAt":datetime.fromisoformat(run["finished_at"].replace("Z","+00:00")).isoformat(timespec="milliseconds").replace("+00:00","Z"),"replayed":True}, "duplicate completion did not return original receipt")
        elif index < 5:
            task_index = [10,0,10][index-2]
            _require(probe["error"] is None and probe["request"]["taskIndex"] == task_index
                     and response["runId"] == run["id"] and response["taskIndex"] == task_index and response["taskId"] == tasks[task_index]["task_id"]
                     and response["replayed"] is True and _epoch(response["finishedAt"]) == _epoch(tasks[task_index]["finished_at"]), "out-of-order predecessor callback changed receipt")
        else:
            _require(response is None and probe["error"] == {"code":"SUCCESSOR_RUN_NOT_CURRENT","status":409}
                     and probe["request"]["predecessorTaskIndex"] == [10,0][index-5], "late successor callback was not safely rejected")
    _require(type(capture["preparedPortCalls"]) is int and capture["preparedPortCalls"] == 0, "late callback touched an executor preparation port")
    return {"facts":{"duplicate_out_of_order_completion":True,"late_callback":True},"probes":7,"runId":target["runId"],
            "scope":"private_callbacks_after_actual_full_completion_not_first_owed_commit_or_artifact_replay",
            "fullScenarioAcceptance":"blocked"}


def verify_pending_transition(reference: dict, *, repository_root: Path | None = None) -> dict:
    root = repository_root or Path(__file__).resolve().parents[3]
    capture = read_reference(root,reference)
    phase,run_id = capture["phase"],capture["runId"]
    _require(capture["schemaVersion"] == "ber-pending-transition-interruption/v1" and phase in {"evaluation","successor_dispatch"}
             and re.fullmatch(r"oid_acceptance_[a-f0-9]{32}",capture["databaseName"]), "pending transition boundary differs")
    _require(capture["sourceBefore"] == capture["sourceAfter"] and capture["sourceBefore"], "pending transition source changed")
    for path,sha in capture["sourceBefore"].items(): read_reference(root,{"path":path,"sha256":sha},json_body=False)
    required = {"armed","beforeCrash","afterStop","resumed"}
    for pointer in capture.get("checkpoints",{}).values(): read_reference(root,pointer)
    if capture.get("failureObservation"): read_reference(root,capture["failureObservation"])
    if not required.issubset(capture.get("checkpoints",{})):
        return {"facts":{},"runId":run_id,"missingVariants":["pending_transition_"+phase],"status":"blocked"}
    states={name:read_reference(root,capture["checkpoints"][name]) for name in required}
    for state in states.values():
        _require(state["identity"]["role"] == "oid_observer" and state["identity"]["read_only"] == "on"
                 and state["identity"]["database_name"] == capture["databaseName"], "pending transition observer not read-only")
        run = _one(state["result"]["run"],"pending run")
        _require(run["id"] == run_id and run["mode"] == "ranked" and run["task_ids"] == TASKS and run["status"] == "running", "pending transition run identity/status differs")
        for event in state["result"]["events"]:
            _require(digest(event["payload_json"]) == event["payload_hash"], "pending transition event hash differs")
    armed,before,stopped,resumed = (states[k] for k in ("armed","beforeCrash","afterStop","resumed"))
    def selected(state,key,index): return [r for r in state["result"][key] if r["task_index"] == index]
    def task(state,index): return _one(selected(state,"tasks",index),"pending task")
    def stable_money_actions(state):
        result=state["result"]
        return {"actions":sorted(selected(state,"actions",8),key=canonical),"receipts":sorted(result["receipts"],key=canonical),"ledger":sorted(result["ledger"],key=canonical)}
    _require(all(stable_money_actions(s) == stable_money_actions(armed) for s in (before,stopped,resumed)), "pending transition changed original H1 action/receipt/money")
    stable_keys=["run_id","task_index","task_id","closure_id","closure_payload_hash","closure_operation_id","closure_reason","closed_at","accepted_action_sequence","action_cutoff_sequence","reconciled_action_sequence","started_at","deadline_at"]
    h1=task(armed,8)
    _require(h1["closure_status"] == "closed" and not selected(armed,"evaluations",8) and not selected(armed,"preparations",9), "pending barrier was not armed before the first owed transition")
    _require(all({k:task(s,8)[k] for k in stable_keys} == {k:h1[k] for k in stable_keys} for s in (before,stopped,resumed)), "pending transition reset original closure/cutoff/clock")
    controller,blocked = before["controllerPid"],capture["blockedPid"]
    locktype,mode = ("relation","RowExclusiveLock") if phase == "evaluation" else ("advisory","ExclusiveLock")
    waiting=[l for l in before["locks"] if l["pid"] == blocked and l["locktype"] == locktype and l["mode"] == mode and l["granted"] is False and controller in l["blocking_pids"]]
    _require(len(waiting) == 1 and any(l["pid"] == controller and l["granted"] is True for l in before["locks"])
             and not any(l["pid"] == blocked for l in stopped["locks"]), "actual blocked worker transaction/rollback not proven")
    restart=capture["restart"]
    stop=capture["stopReceipt"]
    _require(stop["schemaVersion"] == "beta-local-api-stop-receipt/v1" and stop["previousPid"] == restart["previousPid"]
             and (stop["exitCode"] is not None or stop["signal"] is not None) and capture["apiUnavailableAfterStop"] is True
             and _epoch(before["identity"]["observed_at"]) <= _epoch(stop["startedAt"]) <= _epoch(stop["finishedAt"])
             <= _epoch(stopped["identity"]["observed_at"]),"pending interrupted API process exit not proven")
    _require(restart["schemaVersion"] == "beta-local-api-restart-receipt/v1" and restart["previousPid"] != restart["currentPid"] and restart["healthHttpStatus"] == 200
             and _epoch(before["identity"]["observed_at"]) <= _epoch(stopped["identity"]["observed_at"]) <= _epoch(restart["startedAt"])
             <= _epoch(restart["finishedAt"]) <= _epoch(resumed["identity"]["observed_at"]), "pending transition stop/restart causal order invalid")
    final_evaluation=_one(selected(resumed,"evaluations",8),"resumed first H1 grade")
    _require(final_evaluation["closure_id"] == h1["closure_id"] and final_evaluation["task_id"] == "H1"
             and digest(final_evaluation["input_json"]) == final_evaluation["input_hash"] and digest(final_evaluation["result_json"]) == final_evaluation["result_hash"]
             and final_evaluation["result_json"]["status"] == "known" and task(resumed,8)["status"] in {"completed","failed"}, "resumed grade not bound to original closed task")
    graded_event=_event(resumed["result"]["events"],"task.evaluated",8)
    _require(graded_event["payload_json"]["closureId"] == h1["closure_id"] and graded_event["payload_json"]["inputHash"] == final_evaluation["input_hash"]
             and graded_event["payload_json"]["resultHash"] == final_evaluation["result_hash"], "resumed first grade event differs")
    for lease in [l for l in resumed["result"]["leases"] if l["preparation_id"] == _one(selected(resumed,"preparations",8),"H1 preparation")["preparation_id"]]:
        _require(lease["state"] == "fenced" and lease["fence_evidence"]["confirmed"] is True, "resumed predecessor not fenced")
        fp=read_reference(root,lease["fence_evidence"]["evidence"])
        _require(fp["evidence"]["fenceConfirmed"] is True and fp["evidence"]["actualBefGenerationId"] == lease["fence_evidence"]["generationId"], "resumed fence raw generation differs")
    if phase == "evaluation":
        _require(before["table"] == "oid_run_task_evaluation" and not selected(before,"evaluations",8) and not selected(stopped,"evaluations",8), "first grade was committed before the crash")
        _require(not any(e["event_type"] == "task.evaluated" and e["payload_json"].get("taskIndex") == 8 for s in (before,stopped) for e in s["result"]["events"]), "first grade event existed before rollback")
        original_bundle=_one(selected(before,"bundles",8),"sealed first-grade bundle")
        _require(selected(stopped,"bundles",8) == [original_bundle] and digest(original_bundle["bundle_json"]) == original_bundle["bundle_hash"]
                 and final_evaluation["input_json"]["observations"] == original_bundle["bundle_json"]["observations"], "first grade did not resume the original sealed evidence")
        fact="restart_before_first_grade"
    else:
        gate=capture["privateFaultGate"]
        suffix=capture["captureId"].replace("-","")
        _require(gate["functionName"] == "ber_gate_"+suffix and gate["triggerName"] == "ber_gate_dispatch_"+suffix
                 and gate["advisoryKeys"] == [174004007,1+int(suffix[:8],16)%2147483000]
                 and before["advisoryKeys"] == gate["advisoryKeys"]
                 and digest(gate["declaredDDL"]) == gate["declaredDdlSha256"] and len(gate["installed"]) == 1
                 and "BEFORE INSERT ON public.oid_task_preparation_dispatch" in gate["installed"][0]["trigger_definition"]
                 and "run_id='"+run_id+"'::uuid AND task_index=9" in gate["installed"][0]["function_definition"]
                 and "pg_advisory_xact_lock("+str(gate["advisoryKeys"][0])+","+str(gate["advisoryKeys"][1])+")" in gate["installed"][0]["function_definition"]
                 and capture["gateCleanup"] == {"trigger_count":0,"function_count":0}, "private successor fault gate scope/cleanup not proven")
        p=_one(selected(before,"preparations",9),"original committed H2 intent")
        _require(selected(stopped,"preparations",9) == selected(resumed,"preparations",9) == [p]
                 and _one(selected(before,"evaluations",8),"predecessor grade") == final_evaluation
                 and task(before,8)["status"] in {"completed","failed"}, "successor restart rewrote intent or predecessor grade")
        for state in (before,stopped):
            _require(not [d for d in state["result"]["dispatch"] if d["preparation_id"] == p["preparation_id"]]
                     and not [g for g in state["result"]["generations"] if g["preparation_id"] == p["preparation_id"]]
                     and not selected(state,"bindings",9), "H2 dispatch/physical generation existed before blocked claim rolled back")
            _require(not any(e["event_type"] == "task.activated" and e["payload_json"].get("toTaskIndex") == 9 for e in state["result"]["events"]), "H2 activation existed before the interrupted dispatch")
        dispatch=_one([d for d in resumed["result"]["dispatch"] if d["preparation_id"] == p["preparation_id"]],"resumed original preparation dispatch")
        generation=_one([g for g in resumed["result"]["generations"] if g["preparation_id"] == p["preparation_id"]],"resumed generation")
        observation=_one([o for o in resumed["result"]["observations"] if o["preparation_id"] == p["preparation_id"]],"resumed ready observation")
        binding=_one(selected(resumed,"bindings",9),"resumed binding")
        _require(dispatch["state"] == "completed" and task(resumed,9)["status"] == "active" and observation["status"] == "ready"
                 and generation["generation_id"] == observation["generation_id"] == binding["generation_id"]
                 and p["claim_id"] == _one(resumed["result"]["claims"],"same original dispatch claim")["claim_id"], "successor did not resume original intent exactly once")
        activated=_one([e for e in resumed["result"]["events"] if e["event_type"] == "task.activated" and e["payload_json"].get("toTaskIndex") == 9],"once-only H2 activation")
        _require(activated["payload_json"]["preparation"]["preparationId"] == p["preparation_id"]
                 and activated["payload_json"]["preparation"]["generationId"] == generation["generation_id"], "H2 activation not bound to resumed preparation")
        for field in ("fixture_evidence","baseline_evidence"): read_reference(root,observation[field],json_body=False)
        fact="restart_at_successor_activation"
    return {"facts":{fact:True},"phase":phase,"status":"verified_subset","runId":run_id,"fullScenarioAcceptance":"blocked"}


def _validate_admission_versions(states: dict, run_id: str):
    for state in states.values():
        run=_one(state["rows"]["run"],"handoff admission run")
        version=_one(state["rows"]["versions"],"original admission version snapshot")
        snapshot=version["snapshot_json"]
        _require(version["run_id"] == run_id == run["id"] and version["owner_id"] == run["owner_id"] and version["agent_id"] == run["agent_id"]
                 and snapshot["schemaVersion"] == "ranked-agent-version-snapshot/v1" and snapshot["runId"] == run_id
                 and snapshot["ownerId"] == run["owner_id"] and snapshot["agentId"] == run["agent_id"]
                 and digest(snapshot) == version["snapshot_hash"]
                 and _epoch(version["created_at"]) <= _epoch(run["started_at"]) <= _epoch(state["identity"]["observed_at"]),
                 "handoff admission version snapshot binding/hash/origin differs")
    if states:
        admission=_one(next(iter(states.values()))["rows"]["versions"],"immutable admission version")
        _require(all(state["rows"]["versions"] == [admission] for state in states.values()),"handoff restart changed original admission version snapshot")


def verify_completion_handoff(reference: dict, *, repository_root: Path | None = None) -> dict:
    root=repository_root or Path(__file__).resolve().parents[3]
    capture=read_reference(root,reference)
    _require(capture["schemaVersion"] == "ber-completion-handoff-interruption/v1"
             and re.fullmatch(r"oid_acceptance_[a-f0-9]{32}",capture["databaseName"])
             and capture["sourceBefore"] == capture["sourceAfter"] and capture["sourceBefore"],"first handoff boundary/source invalid")
    for path,sha in capture["sourceBefore"].items(): read_reference(root,{"path":path,"sha256":sha},json_body=False)
    states={name:read_reference(root,pointer) for name,pointer in capture["checkpoints"].items()}
    if capture.get("failureObservation"): read_reference(root,capture["failureObservation"])
    run_id=capture["runId"]
    for state in states.values():
        identity=state["identity"];run=_one(state["rows"]["run"],"handoff run")
        _require(identity["role"] == "oid_observer" and identity["read_only"] == "on" and identity["database_name"] == capture["databaseName"]
                 and run["id"] == run_id and run["mode"] == "ranked" and run["task_ids"] == TASKS,"handoff raw observer/run differs")
        for event in state["rows"]["events"]: _require(digest(event["payload_json"]) == event["payload_hash"],"handoff raw event hash differs")
    _validate_admission_versions(states,run_id)
    if not {"armed","beforeCrash","afterStop","resumed"}.issubset(states):
        return {"runId":run_id,"facts":{},"status":"blocked","missingVariants":["restart_at_completion_handoff"]}
    before,stopped,resumed=(states[n] for n in ("beforeCrash","afterStop","resumed"))
    def original(state): return {k:sorted(state["rows"][k],key=canonical) for k in ("evaluations","actions","receipts","ledger","bindings","preparations","leases","bundles","versions")}
    _require(original(before) == original(stopped) == original(resumed),"handoff crash changed original grades/actions/receipts/money/preparations")
    def immutable_run(state): return {k:v for k,v in state["rows"]["run"][0].items() if k not in {"status","finished_at"}}
    def immutable_tasks(state): return [{k:v for k,v in task.items() if k not in {"status","finished_at"}} for task in state["rows"]["tasks"]]
    _require(immutable_run(before) == immutable_run(stopped) == immutable_run(resumed)
             and immutable_tasks(before) == immutable_tasks(stopped) == immutable_tasks(resumed),"handoff restart changed original release/cutoffs/deadlines/finance policy")
    for state in (before,stopped,resumed):
        rows=state["rows"]
        _require(len(rows["tasks"]) == len(rows["evaluations"]) == len(rows["leases"]) == 12,"first handoff lacks full12 evidence")
        for index,task in enumerate(rows["tasks"]):
            grade=_one([e for e in rows["evaluations"] if e["task_index"] == index],"handoff immutable grade")
            _require(task["task_index"] == index and task["task_id"] == TASKS[index] and task["closure_status"] == "closed"
                     and grade["closure_id"] == task["closure_id"] and grade["result_json"]["status"] == "known"
                     and digest(grade["input_json"]) == grade["input_hash"] and digest(grade["result_json"]) == grade["result_hash"],"handoff grade not bound to original closed cutoff")
            expected_active=index == 11 and state is not resumed
            _require((task["status"] == "active" and task["finished_at"] is None) if expected_active else task["status"] in {"completed","failed"},"handoff transaction terminalized a task before commit")
        for lease in rows["leases"]:
            fence=lease["fence_evidence"];body=read_reference(root,fence["evidence"])
            _require(lease["state"] == "fenced" and fence["confirmed"] is True and body["evidence"]["fenceConfirmed"] is True
                     and body["preparationId"] == lease["preparation_id"] and body["evidence"]["actualBefGenerationId"] == fence["generationId"],"handoff source generation not fenced")
        debit=_one(rows["ledger"],"handoff original bonus debit")
        _require(debit["entry_type"] == "debit" and debit["source_kind"] == "tester_bonus" and int(debit["amount_units"]) > 0,"handoff fabricated finance authority")
    for state in (before,stopped):
        rows=state["rows"]
        _require(rows["run"][0]["status"] == "running" and not rows["handoffs"] and not rows["results"]
                 and not any(e["event_type"] in {"run.completed","run.ranked_eligible"} for e in rows["events"]),"first handoff already committed before interrupted transaction")
    controller,writer=before["controllerPid"],capture["blockedPid"]
    _require(any(l["pid"] == writer and l["mode"] == "RowExclusiveLock" and l["granted"] is False and controller in l["blocking_pids"] for l in before["locks"])
             and any(l["pid"] == controller and l["mode"] == "ShareLock" and l["granted"] is True for l in before["locks"])
             and not any(l["pid"] == writer for l in stopped["locks"]),"first handoff writer/rollback not actually observed")
    stop,restart=capture["stopReceipt"],capture["restart"]
    _require(stop["schemaVersion"] == "beta-local-api-stop-receipt/v1" and restart["schemaVersion"] == "beta-local-api-restart-receipt/v1"
             and stop["previousPid"] == restart["previousPid"] != restart["currentPid"] and (stop["exitCode"] is not None or stop["signal"] is not None)
             and capture["apiUnavailableAfterStop"] is True and restart["healthHttpStatus"] == 200
             and _epoch(before["identity"]["observed_at"]) <= _epoch(stop["startedAt"]) <= _epoch(stop["finishedAt"])
             <= _epoch(stopped["identity"]["observed_at"]) <= _epoch(restart["startedAt"]) <= _epoch(restart["finishedAt"])
             <= _epoch(resumed["identity"]["observed_at"]),"first handoff process stop/restart causal order invalid")
    rows=resumed["rows"];handoff=_one(rows["handoffs"],"first handoff");result=_one(rows["results"],"first verified result");version=_one(rows["versions"],"first version snapshot")
    completed=_event(rows["events"],"run.completed");eligible=_event(rows["events"],"run.ranked_eligible")
    _require(rows["run"][0]["status"] == "completed" and rows["slots"] == [] and rows["claims"] and all(c["status"] == "released" for c in rows["claims"])
             and digest(handoff["handoff_json"]) == handoff["handoff_hash"] == eligible["payload_hash"]
             and handoff["completion_event_hash"] == handoff["handoff_json"]["completionEventHash"] == completed["payload_hash"]
             and digest({k:v for k,v in result["aggregate_json"].items() if k != "aggregateHash"}) == result["aggregate_hash"] == handoff["aggregate_hash"]
             and digest(version["snapshot_json"]) == version["snapshot_hash"] == handoff["version_snapshot_hash"] == result["version_snapshot_hash"],"first owed handoff/result/version/resource release inconsistent")
    proofs=result["aggregate_json"]["taskProofs"]
    _require(len(proofs) == 12 and {p["taskIndex"] for p in proofs} == set(range(12)),"first handoff lost or duplicated task proofs")
    for proof in proofs:
        grade=_one([e for e in rows["evaluations"] if e["task_index"] == proof["taskIndex"]],"handoff original proof grade")
        preparation=_one([p for p in rows["preparations"] if p["task_index"] == proof["taskIndex"]],"handoff original proof preparation")
        lease=_one([l for l in rows["leases"] if l["preparation_id"] == preparation["preparation_id"]],"handoff original proof fence")
        _require(proof["taskId"] == TASKS[proof["taskIndex"]] and proof["inputHash"] == grade["input_hash"] and proof["resultHash"] == grade["result_hash"]
                 and proof["result"] == grade["result_json"] and proof["fenceEvidenceHash"] == lease["fence_evidence"]["evidence"]["sha256"],"handoff proof replaced original grade/fence")
    return {"facts":{"restart_at_completion_handoff":True},"runId":run_id,"status":"verified_subset","fullScenarioAcceptance":"blocked"}


def verify_fault_core(reference: dict, *, repository_root: Path | None = None) -> dict:
    """Reuse the existing independent S1 recovery semantics without claiming H1 coverage."""
    root = repository_root or Path(__file__).resolve().parents[3]
    capture = read_reference(root,reference)
    _require(capture.get("schemaVersion") == "ber-fault-recovery-core-capture/v1", "unsupported fault-core capture")
    from tests.bdd.adapters.beta_poc_recovery_verifier import _verify_provenance, verify_local_recovery_result
    database,_ = _verify_provenance(capture,root)
    result = capture["result"]
    facts = verify_local_recovery_result(result,database,repository_root=root)
    return {"status":"verified_subset","boundary":"actual_S1_committed_response_loss_recovery_and_exhaustion",
            "databaseName":database,"facts":facts,"fullScenarioAcceptance":"blocked",
            "missingVariants":["exact_H1_cutoff_and_grading_matrix","owner_cancel_revoke_orderings","stale_callback","forged_failure_authority"]}


def verify_first_refund_crash(proof: dict, *, database: str, action: dict, binding: dict, repository_root: Path | None = None) -> dict:
    """Derive the first owed refund barrier from actual locks and committed rows."""
    root = repository_root or Path(__file__).resolve().parents[3]
    _require(proof["schemaVersion"] == "ber-first-refund-crash/v1" and re.fullmatch(r"oid_acceptance_[a-f0-9]{32}",database), "refund crash boundary invalid")
    names = ("armed","beforeCrash","afterStop","afterFinalization")
    if not all(proof.get(k) for k in names):
        return {"facts":{},"status":"blocked","missingVariants":["crash_before_first_authorized_refund_commit"]}
    docs = {k:read_reference(root,proof[k]) for k in names}
    run_id,action_id = proof["runId"],proof["actionId"]
    _require(run_id == binding["runId"] and action_id == action["actionId"],"refund crash belongs to another original effect")
    schemas = dict(zip(names,("barrier-armed","before-crash","after-stop","after-finalization")))
    for name,doc in docs.items():
        _require(doc["schemaVersion"] == "ber-first-refund-"+schemas[name]+"/v1" and doc["runId"] == run_id and doc["actionId"] == action_id,"refund checkpoint identity differs")
        state=doc["observation"]; identity=state["identity"]
        _require(identity["role"] == "oid_observer" and identity["readonly"] == "on" and identity["database_name"] == database and state["run"]["id"] == run_id,"refund checkpoint observer differs")
    armed,before,stopped,final = (docs[k] for k in names)
    controller=before["controllerPid"]
    _require(armed["databaseName"] == database and armed["controllerPid"] == controller == stopped["controllerPid"]
             and armed["control"] == "share_table_lock_no_business_write" and before["armed"] == proof["armed"],"refund barrier not bound")
    stable_source=None
    for doc in (before,stopped,final):
        source=doc["source"]
        from tests.bdd.adapters.beta_poc_recovery_verifier import _source_operation
        _source_operation(source,action,binding,name="firstRefundCrash.source")
        body={k:source[k] for k in ("result","selectedExecutions","recoverySource")}
        _require(_wire_digest(body) == doc["sourceStableBodySha256"] == proof["sourceStableBodySha256"],"refund source raw hash differs")
        if stable_source is None: stable_source=body
        _require(body == stable_source,"original source effect changed through refund crash")
        effect=_one(source["result"],"original refund source effect")
        _require(effect["status"] == "settled" and effect["receiptStatus"] == "success" and effect["generationStatus"] == "fenced","refund source effect not successful/fenced")
    before_state,stop_state,final_state=(d["observation"] for d in (before,stopped,final))
    def zero(state): return state["refunds"] == state["refundLedger"] == []
    def cancelled_fenced(state):
        run=state["run"]; lease=_one(state["execution"],"refund predecessor lease"); fence=lease["fence_evidence"]
        event=_one(state["cancellation"],"refund cancellation")
        _require(run["status"] == "cancelled" and run["cancellation_reason"] == "coordinator_platform_failure"
                 and lease["lease_state"] == "fenced" and fence["confirmed"] is True
                 and all(fence[key] == lease[column] for key,column in (("preparationId","preparation_id"),("environmentId","environment_id"),("leaseId","lease_id"),("generationId","generation_id")))
                 and event["event_type"] == "run.cancelled.after_start" and digest(event["payload_json"]) == event["payload_hash"]
                 and event["payload_json"]["fenceEvidenceHash"] == run["cancellation_evidence_hash"],"refund source generation/cancellation not fenced")
        raw=read_reference(root,fence["evidence"])
        _require(raw["evidence"]["fenceConfirmed"] is True and raw["evidence"]["actualBefGenerationId"] == lease["generation_id"],"refund fence raw generation differs")
    _require(zero(armed["observation"]),"first refund already committed before barrier")
    for state in (before_state,stop_state,stopped["immediatelyBeforeStop"]):
        cancelled_fenced(state); _require(zero(state),"refund committed before interrupted transaction rolled back")
    waiting=[l for l in before_state["locks"] if l["mode"] == "RowExclusiveLock" and l["granted"] is False and controller in l["blocking_pids"]]
    _require(waiting and any(l["pid"] == controller and l["granted"] is True and l["mode"] == "ShareLock" for l in before_state["locks"])
             and any(l["pid"] in {w["pid"] for w in waiting} and not l["granted"] and controller in l["blocking_pids"] for l in stopped["immediatelyBeforeStop"]["locks"])
             and not any(l["pid"] in {w["pid"] for w in waiting} for l in stop_state["locks"]),"first refund actual blocked writer/rollback missing")
    restart=proof["restartReceipt"]
    _require(restart["schemaVersion"] == "beta-local-api-restart-receipt/v1" and restart["healthHttpStatus"] == 200
             and restart["previousPid"] != restart["currentPid"] and stopped["apiUnavailable"] is True
             and _epoch(before_state["identity"]["observed_at"]) <= _epoch(stopped["stopStartedAt"]) <= _epoch(stopped["stopFinishedAt"])
             <= _epoch(restart["startedAt"]) <= _epoch(restart["finishedAt"]) <= _epoch(final_state["identity"]["observed_at"]),"refund stop/restart causal order differs")
    recovery=final_state["recovery"]; refund=_one(final_state["refunds"],"first official refund"); ledger=_one(final_state["refundLedger"],"first source refund ledger")
    _require(final_state["run"]["status"] == "failed" and final_state["run"]["terminal_reason"] == "platform_failure_recovery_exhausted"
             and recovery["run_id"] == run_id and recovery["action_id"] == action_id and recovery["status"] == "refunded"
             and _epoch(recovery["deadline_at"]) == _epoch(recovery["started_at"])+180
             and refund["run_id"] == run_id and refund["evidence_hash"] == recovery["latest_evidence_hash"]
             and int(refund["bonus_refunded_units"]) > 0 and int(ledger["amount_units"]) == int(refund["bonus_refunded_units"])
             and ledger["entry_type"] == "refund" and ledger["source_kind"] == "tester_bonus"
             and int(ledger["available_delta_units"])+int(ledger["expired_delta_units"]) == int(ledger["amount_units"]),"first authorized refund not committed exactly once")
    for state in (before_state,stop_state):
        _require(all(state["recovery"][k] == recovery[k] for k in ("run_id","action_id","started_at","deadline_at","clock_excluded_ms")),"refund restart reset recovery identity/clock")
        _require([{k:a[k] for k in ("id","operation_id","payload_hash","action_kind")} for a in state["actions"]]
                 == [{k:a[k] for k in ("id","operation_id","payload_hash","action_kind")} for a in final_state["actions"]],"refund crash changed original economic action")
    original_tx=_one(final["source"]["result"],"original settled transaction")["transactionHash"].lower()
    for state in (before_state,stop_state,final_state):
        _require(all(a["transaction_hash"] is None or a["transaction_hash"].lower() == original_tx for a in state["actions"]),"refund receipt reconciliation invented another transaction")
    return {"facts":{"crash_before_first_authorized_refund_commit":True},"runId":run_id,"status":"verified_subset","fullScenarioAcceptance":"blocked"}


UNKNOWN_CASES = {"missing_recover","conflicting_recover","missing_exhaust_restart","cancel_before_recover","recover_before_cancel"}
UNKNOWN_FACTS = ["raw_unknown_reasons","recovery_deadline","closure_evaluation_binding","terminal_and_refund_source","no_public_result",
                 "missing_or_conflicting_receipt","unknown_preflight","recovery_success_or_exhaustion","cancel_recovery_race",
                 "forged_failure_report","one_recovery_terminal_transition","at_most_one_authorized_source_refund","retained_unknown"]


def _unknown_state(value: dict, database: str, run_id: str) -> tuple[dict,dict]:
    identity,result = value["identity"],value["result"]
    _require(identity["role"] == "oid_observer" and identity["read_only"] == "on" and identity["database_name"] == database, "unknown observer identity differs")
    _require(result["run"]["id"] == run_id and result["run"]["mode"] == "ranked", "unknown run identity differs")
    for event in result["events"]:
        _require(digest(event["payload_json"]) == event["payload_hash"], "unknown event payload hash differs")
    task = _one([t for t in result["tasks"] if t["task_index"] == 8 and t["task_id"] == "H1"], "unknown H1 task")
    _require(task["closure_status"] == "closed" and task["closure_id"] and task["closed_at"]
             and int(task["accepted_action_sequence"]) == int(task["action_cutoff_sequence"]) == int(task["reconciled_action_sequence"]), "unknown H1 cutoff unresolved")
    _require(abs(_epoch(task["evaluation_retry_deadline"])-_epoch(task["closed_at"])-180) < 0.0001, "unknown deadline origin reset or wrong bound")
    return result,task


def _wire_digest(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()).hexdigest()


def _unknown_paid_packets(pointers, root, run_id, task, initial, binding, *, known=False):
    matched = False
    for pointer in pointers:
        packet = read_reference(root,pointer)
        _require(packet["schemaVersion"] == "bts-paid-data-run-observation-capture/v1"
                 and packet["binding"]["runId"] == run_id and packet["binding"]["taskId"] == "H1"
                 and packet["binding"]["releaseIdentity"] == initial["run"]["release_identity"]
                 and packet["binding"]["manifestHash"] == initial["run"]["manifest_hash"]
                 and packet["closure"]["closureId"] == task["closure_id"]
                 and packet["closure"]["payloadHash"] == task["closure_payload_hash"]
                 and packet["closure"]["actionCutoffSequence"] == int(task["action_cutoff_sequence"])
                 and packet["execution"]["generationId"] == binding["generation_id"], "raw paid observation binding differs")
        refs = {}
        _references(packet,refs)
        for path,sha in refs.items(): read_reference(root,{"path":path,"sha256":sha},json_body=False)
        owner_actions = {a["id"]:a for a in initial["actions"] if a["task_index"] == 8}
        _require({a["actionId"] for a in packet["ownerActions"]} == set(owner_actions)
                 and all(a["ownerOperationId"] == owner_actions[a["actionId"]]["operation_id"]
                         and a["commandSha256"] == owner_actions[a["actionId"]]["payload_hash"] for a in packet["ownerActions"]), "raw observation changed original owner actions")
        effects = packet["rpc"]["paymentEffects"]
        if known:
            matched |= packet["coverage"]["status"] == "observed" and len(effects) == 3 and all(e["verification"] == "observed" for e in effects)
        else:
            matched |= packet["coverage"]["status"] in {"partial","unknown","contradictory"} and any(
                e["verification"] in {"unknown","contradictory"} and isinstance(e.get("reasonCode"),str) and e["reasonCode"] for e in effects)
    return bool(matched)


def _unknown_case_context(matrix: dict) -> dict:
    cases=matrix.get("caseResults",[])
    _require(len({c["name"] for c in cases}) == len(cases) and all(c["name"] in UNKNOWN_CASES for c in cases),"unknown matrix case declarations invalid")
    context={}
    for index,case in enumerate(cases):
        run_id=case.get("runId")
        if run_id is None:
            _require(not case.get("checkpoints"),"unknown checkpoint lacks a declared run")
            continue
        _require(isinstance(run_id,str) and re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}",run_id)
                 and run_id not in context,"unknown matrix run identities invalid or duplicated")
        context[run_id]={"name":case["name"],"index":index}
    return context


def _unknown_case(case: dict, database: str, root: Path, *, declared_runs: dict | None = None) -> dict:
    name,run_id = case["name"],case.get("runId")
    _require(name in UNKNOWN_CASES, "unexpected unknown matrix variant")
    checkpoints = {c["phase"]:c for c in case.get("checkpoints",[])}
    _require(len(checkpoints) == len(case.get("checkpoints",[])), "duplicate unknown checkpoints")
    if "candidate_unknown" not in checkpoints:
        return {"name":name,"complete":False,"missing":["candidate_unknown"],"facts":{}}
    initial_checkpoint = checkpoints["candidate_unknown"]
    initial,task = _unknown_state(initial_checkpoint["state"],database,run_id)
    genuine = read_reference(root,case["genuineCapture"]["evidence"])
    launch = genuine["launchIntent"]
    _require(genuine["schemaVersion"] == "genuine-ranked-worker-owner-run-capture/v1"
             and genuine["mode"] == "ranked" and genuine["taskIds"] == TASKS
             and genuine["run"]["runId"] == run_id and genuine["run"]["database"]["id"] == run_id
             and launch["browserHttpStatus"] in {200,201} and launch["database"]["id"] == launch["intentId"]
             and launch["database"]["status"] == "pending" and launch["database"]["run_id"] is None
             and launch["operationId"] == genuine["run"]["createIntentOperationId"]
             and any(s["name"] == "owner_run_intent_ui_and_readonly_database" and s["status"] == "verified"
                     and s["intentId"] == launch["intentId"] for s in genuine["stages"]), "unknown case lacks actual browser launch to durable admission proof")
    baseline_task = {k:v for k,v in task.items() if k not in {"status","evaluation_retry_expired"}}
    _require(initial["run"]["status"] == "running" and not any(e["task_index"] == 8 for e in initial["evaluations"])
             and initial["publications"] == {"handoffs":0,"results":0} and initial["recoveries"] == [], "candidate was already graded, published or financially recovered")
    lifecycle = []
    for pointer in initial_checkpoint.get("progress",[]):
        body = read_reference(root,pointer)
        _require(body == pointer["document"] and body.get("runId") == run_id and body.get("taskIndex") == 8, "lifecycle raw binding differs")
        if body.get("reasonCode") == "candidate_evaluation_unknown": lifecycle.append(body)
    _require(lifecycle, "no actual unknown preflight lifecycle evidence")
    raw_reasons = any(isinstance(p.get("evaluationUnknownReasons"),list) and p["evaluationUnknownReasons"]
                      and all(isinstance(x,str) and x for x in p["evaluationUnknownReasons"]) for p in lifecycle)
    confirmed = case["confirmedPayments"]
    identity = confirmed["identity"]
    _require(identity["role"] == "bef_observer" and identity["database_name"] == "bef" and identity["read_only"] == "on", "payment observer not independently read-only")
    payments = confirmed["result"]["payments"]
    binding = confirmed["result"]["binding"]
    paid_actions = [a for a in initial["actions"] if a["task_index"] == 8 and a["action_kind"] == "pay"]
    _require(len(payments) == len(paid_actions) == 3 and len({p["transaction_hash"] for p in payments}) == 3
             and all(p["receipt_status"] == "success" and int(p["amount_units"]) > 0 and p["amount_units"] == p["token_delta_units"] for p in payments)
             and {p["transaction_hash"].lower() for p in payments} == {a["transaction_hash"].lower() for a in paid_actions}, "three original paid H1 effects not proven")
    _require(binding["task_index"] == 8 and all(a["receipt_status"] == "observed" and a["outbox_status"] == "delivered" for a in initial["actions"] if a["task_index"] == 8), "original H1 action receipts not resolved")
    unknown_packets = _unknown_paid_packets(initial_checkpoint.get("rawObservationPackets",[]),root,run_id,task,initial,binding)
    fault = case["fault"]
    interventions = fault.get("interventions",[])
    _require(fault.get("schemaVersion") == "ber-observer-receipt-fault/v1" and interventions, "actual observer receipt fault missing")
    context=declared_runs or {run_id:{"name":name,"index":0}}
    _require(run_id in context and context[run_id]["name"] == name,"unknown fault case is not declared")
    current_interventions=[]
    for intervention in interventions:
        original,delivered = intervention["originalReceipt"],intervention["deliveredReceipt"]
        record_run=intervention["runId"]
        _require(record_run in context,"receipt fault contains an undeclared foreign run")
        expected_mode="conflicting" if context[record_run]["name"] == "conflicting_recover" else "missing"
        _require(intervention["taskIndex"] == 8 and intervention["taskId"] == "H1" and intervention["mode"] == expected_mode
                 and int(original["status"],16) == 1 and original["transactionHash"].lower() == intervention["transactionHash"]
                 and _wire_digest(original) == intervention["originalReceiptSha256"] and _wire_digest(delivered) == intervention["deliveredReceiptSha256"]
                 and type(intervention["count"]) is int and intervention["count"] >= 1
                 and _epoch(intervention["firstObservedAt"]) <= _epoch(intervention["lastObservedAt"]), "receipt fault raw wire history invalid")
        if intervention["mode"] == "missing":
            _require(delivered is None, "missing-receipt fault did not deliver null")
        else:
            _require(intervention["mode"] == "conflicting" and delivered == {**original,"status":"0x0"}, "conflicting receipt fault changed unrelated fields")
        if record_run == run_id:
            _require(intervention["closureId"] == task["closure_id"]
                     and intervention["transactionHash"] in {p["transaction_hash"].lower() for p in payments}
                     and _epoch(intervention["firstObservedAt"]) >= _epoch(task["closed_at"]), "fault did not target the actual closed paid H1 receipt")
            current_interventions.append(intervention)
        else:
            # The proxy snapshot is cumulative. Earlier declared cases remain raw
            # context, never evidence for this run's unknown/recovery authority.
            _require(context[record_run]["index"] < context[run_id]["index"]
                     and _epoch(intervention["lastObservedAt"]) < _epoch(task["closed_at"]),"foreign receipt fault is not a preceding declared case")
    _require(current_interventions,"current run has no actual receipt fault")
    state_results = {}
    for phase,checkpoint in checkpoints.items():
        state,current = _unknown_state(checkpoint["state"],database,run_id)
        _require({k:v for k,v in current.items() if k not in {"status","evaluation_retry_expired"}} == baseline_task, "cutoff/closure/deadline changed during unknown recovery")
        _require(state["money"] == initial["money"], "unknown grading changed original money or minted refund")
        _require(state["recoveries"] == [], "unknown grading invented platform recovery/refund authority")
        _require([a for a in state["actions"] if a["task_index"] == 8] == [a for a in initial["actions"] if a["task_index"] == 8], "unknown grading repeated or rewrote H1 effects")
        if phase == "after_restart":
            _require(state["run"]["status"] == "running"
                     and _epoch(checkpoint["state"]["identity"]["database_now"]) < _epoch(task["evaluation_retry_deadline"]),
                     "restart cancelled unknown grading before its original bound")
        if phase == "restart_grace_unknown":
            restart=case["restart"]
            _require(restart["schemaVersion"] == "beta-local-api-restart-receipt/v1" and restart["previousPid"] != restart["currentPid"]
                     and restart["healthHttpStatus"] == 200 and state["run"]["status"] == "running"
                     and not any(e["task_index"] == 8 for e in state["evaluations"])
                     and _epoch(task["closed_at"]) <= _epoch(restart["startedAt"]) <= _epoch(restart["finishedAt"])
                     and _epoch(restart["finishedAt"])+2 <= _epoch(checkpoint["state"]["identity"]["database_now"]) < _epoch(task["evaluation_retry_deadline"]),
                     "restart did not preserve the original unknown grading grace window")
            old_paths={p["path"] for p in initial_checkpoint["progress"]}
            fresh=[]
            for pointer in checkpoint.get("progress",[]):
                body=read_reference(root,pointer)
                _require(body == pointer["document"] and body["runId"] == run_id and body["taskIndex"] == 8,"restarted lifecycle raw binding differs")
                if pointer["path"] not in old_paths and body.get("reasonCode") == "candidate_evaluation_unknown": fresh.append(body)
            _require(fresh and _unknown_paid_packets(checkpoint.get("rawObservationPackets",[]),root,run_id,task,initial,binding),"restarted worker unknown preflight not independently observed")
        if phase == "exhausted":
            _require(state["run"]["status"] == "cancelled"
                     and state["run"]["cancellation_reason"] == "coordinator_evaluation_unknown"
                     and _epoch(state["run"]["cancellation_requested_at"]) >= _epoch(task["evaluation_retry_deadline"]),
                     "unknown grading cancelled early or used an unrelated terminal reason")
        # No publication while evidence remains unknown/incomplete. A later fully
        # recovered Ranked is allowed to publish under its original eligibility rules.
        if phase not in {"full_ranked_completed"}:
            _require(state["publications"] == {"handoffs":0,"results":0}, "incomplete run published a ranked result")
        state_results[phase] = state
    forged = case.get("forgedReport")
    forged_ok = False
    if forged:
        before,_ = _unknown_state(forged["before"],database,run_id)
        after,_ = _unknown_state(forged["after"],database,run_id)
        _require(forged["httpStatus"] == 201 and len(after["reports"]) == len(before["reports"])+1
                 and after["money"] == before["money"] and after["recoveries"] == before["recoveries"] == []
                 and after["publications"] == before["publications"] == {"handoffs":0,"results":0}
                 and not any(e["task_index"] == 8 for e in after["evaluations"]), "participant report changed recovery/refund/grade authority")
        forged_ok = True
    required = {"missing_recover":["restart_grace_unknown","recovered_known","full_ranked_completed"],
                "conflicting_recover":["recovered_known","full_ranked_completed"],
                "missing_exhaust_restart":["after_restart","exhausted"],
                "cancel_before_recover":["cancelled_before_recovery","after_stale_recovery"],
                "recover_before_cancel":["recovered_known","cancelled_after_recovery"]}[name]
    missing = [p for p in required if p not in state_results]
    if not unknown_packets: missing.append("raw_unknown_observation_packet")
    if "recovered_known" in checkpoints:
        if not _unknown_paid_packets(checkpoints["recovered_known"].get("rawObservationPackets",[]),root,run_id,task,initial,binding,known=True):
            missing.append("raw_recovered_observation_packet")
    closure_eval = True
    for phase,state in state_results.items():
        for evaluation in [e for e in state["evaluations"] if e["task_index"] == 8]:
            _require(evaluation["closure_id"] == task["closure_id"] and evaluation["manifest_hash"] == initial["run"]["manifest_hash"]
                     and evaluation["release_identity"] == initial["run"]["release_identity"] and evaluation["task_id"] == "H1"
                     and digest(evaluation["input_json"]) == evaluation["input_hash"] and digest(evaluation["result_json"]) == evaluation["result_hash"]
                     and evaluation["result_json"]["status"] == "known", "recovered evaluation closure/input/result differs")
            _require(evaluation["input_json"]["run"]["runId"] == run_id and evaluation["input_json"]["run"]["taskId"] == "H1"
                     and evaluation["input_json"]["run"]["acceptedActionCutoffSequence"] == int(task["action_cutoff_sequence"]), "recovered input cutoff differs")
            refs = {}
            _references(evaluation["input_json"],refs)
            for path,sha in refs.items(): read_reference(root,{"path":path,"sha256":sha},json_body=False)
            evaluated = _event(state["events"],"task.evaluated",8)
            _require(evaluated["payload_json"]["closureId"] == task["closure_id"] and evaluated["payload_json"]["resultHash"] == evaluation["result_hash"]
                     and _epoch(evaluated["created_at"]) < _epoch(task["evaluation_retry_deadline"]), "recovered grade event differs or exceeds original retry bound")
    terminal_ok = False
    resources_complete = False
    if not missing:
        final_phase = required[-1]
        final = state_results[final_phase]
        if name in {"missing_recover","conflicting_recover"}:
            _require(final["run"]["status"] == "completed" and len(final["evaluations"]) == 12
                     and all(e["result_json"]["status"] == "known" for e in final["evaluations"])
                     and final["publications"] == {"handoffs":1,"results":1}, "recovered full Ranked did not complete normally")
            _event(final["events"],"run.completed");_event(final["events"],"run.ranked_eligible")
        else:
            _require(final["run"]["status"] == "cancelled" and final["run"]["terminal_reason"] == final["run"]["cancellation_reason"], "unknown terminal path inconsistent")
            requested = _event(final["events"],"run.cancellation_requested")
            cancelled = _event(final["events"],"run.cancelled.after_start")
            _require(requested["sequence"] < cancelled["sequence"] and requested["payload_json"]["reason"] == final["run"]["cancellation_reason"]
                     and cancelled["payload_json"]["reason"] == final["run"]["cancellation_reason"] and cancelled["source"] == "executor", "cancellation terminal path duplicated or unbound")
            if name in {"cancel_before_recover","recover_before_cancel"}:
                cancel = case["cancel"]
                _require(cancel["boundary"] == "actual_owner_browser_cancel_control_backend" and cancel["runId"] == run_id
                         and cancel["httpStatus"] == 200 and requested["source"] == "owner", "cancel race did not use actual owner browser authority")
                if name == "recover_before_cancel":
                    _require(_event(final["events"],"task.evaluated",8)["sequence"] < requested["sequence"], "cancel/recovery ordering differs")
            if name == "missing_exhaust_restart":
                restart = case["restart"]
                _require(restart["schemaVersion"] == "beta-local-api-restart-receipt/v1" and restart["previousPid"] != restart["currentPid"]
                         and restart["healthHttpStatus"] == 200
                         and _epoch(task["closed_at"]) <= _epoch(restart["startedAt"]) <= _epoch(restart["finishedAt"]) < _epoch(task["evaluation_retry_deadline"])
                         and _epoch(final["run"]["cancellation_requested_at"]) >= _epoch(task["evaluation_retry_deadline"])
                         and final["run"]["cancellation_reason"] == "coordinator_evaluation_unknown"
                         and not any(e["task_index"] == 8 for e in final["evaluations"]), "unknown exhaustion reset deadline, invented grade or cancelled early")
            elif name == "cancel_before_recover":
                _require(not any(e["task_index"] == 8 for e in final["evaluations"])
                         and state_results["cancelled_before_recovery"]["run"] == final["run"], "late recovery reopened cancelled run")
        _require(final["slots"] == [] and final["claims"] and all(c["status"] == "released" for c in final["claims"]), "unknown terminal retained execution slot/claim")
        preparations = final.get("preparations")
        resources_complete = isinstance(preparations,list) and bool(preparations)
        for execution in preparations if resources_complete else final["execution"]:
            _require(execution["lease_state"] == "fenced" and execution["fence_evidence"]["confirmed"] is True, "unknown terminal leaked preparation generation")
            fence = execution["fence_evidence"]
            body = read_reference(root,fence["evidence"])
            _require(body["preparationId"] == execution["preparation_id"] and body["evidence"]["fenceConfirmed"] is True
                     and body["evidence"]["actualBefGenerationId"] == fence["generationId"], "unknown fence raw generation differs")
        terminal_ok = True
    return {"name":name,"runId":run_id,"complete":not missing and terminal_ok and resources_complete,
            "missing":missing+([] if resources_complete else ["all_created_preparation_resource_evidence"]),
            "facts":{"raw_unknown_reasons":bool(raw_reasons and unknown_packets),"unknown_preflight":unknown_packets,"missing_or_conflicting_receipt":True,
                     "recovery_deadline":True,"closure_evaluation_binding":closure_eval,"forged_failure_report":forged_ok,
                     "no_public_result":True,"at_most_one_authorized_source_refund":True,"retained_unknown":True,
                     "terminal_and_refund_source":terminal_ok,"one_recovery_terminal_transition":terminal_ok}}


def _unknown_capture_inventory(reference: dict, root: Path) -> tuple:
    outer = read_reference(root,reference,unknown_matrix_document=True)
    if outer.get("schemaVersion") == "ber-unknown-grading-matrix-assembly/v1":
        refs=outer.get("captures")
        _require(isinstance(refs,list) and refs and len(refs) <= 5,"unknown assembly capture inventory invalid")
        hashes=[pointer.get("sha256") for pointer in refs]
        _require(len(set(hashes)) == len(hashes),"unknown assembly duplicated capture selection")
        selections=outer.get("selections")
        _require(isinstance(selections,dict) and set(selections) == set(hashes),"unknown assembly needs explicit selections for every capture hash")
        parts=[];selected_by_capture={}
        for pointer in refs:
            document=read_reference(root,pointer,unknown_matrix_document=True)
            _require(document.get("schemaVersion") != "ber-unknown-grading-matrix-assembly/v1","nested unknown assembly not allowed")
            names=selections[pointer["sha256"]]
            _require(isinstance(names,list) and names and all(isinstance(name,str) and name in UNKNOWN_CASES for name in names)
                     and len(set(names)) == len(names),"unknown assembly duplicated or invalid case selection")
            capture_id=document.get("captureId")
            _require(isinstance(capture_id,str) and capture_id not in selected_by_capture,"unknown assembly duplicated capture identity")
            selected_by_capture[capture_id]=set(names)
            nested,_=_unknown_capture_inventory(pointer,root)
            parts.extend(nested)
        _require(parts and all(p[0]["provenance"]["inputHashesBefore"] == parts[0][0]["provenance"]["inputHashesBefore"] for p in parts),"unknown assembly mixed source inventories")
        return parts,selected_by_capture
    _require(outer.get("schemaVersion") == "ber-unknown-grading-capture/v1", "unsupported unknown matrix capture")
    if not outer.get("result",{}).get("evidence"):
        # Even an incomplete supplied capture must retain source provenance.
        from tests.bdd.adapters.beta_poc_recovery_verifier import _verify_provenance
        _verify_provenance(outer,root)
        return [],None
    from tests.bdd.adapters.beta_poc_recovery_verifier import _verify_provenance
    database,_ = _verify_provenance(outer,root)
    matrix = read_reference(root,outer["result"]["evidence"],unknown_matrix_document=True)
    _require(matrix == {k:v for k,v in outer["result"].items() if k != "evidence"}
             and matrix["schemaVersion"] == "ber-unknown-grading-matrix/v1"
             and set(matrix["caseInventory"]) == UNKNOWN_CASES and len(matrix["caseInventory"]) == len(UNKNOWN_CASES), "matrix immutable evidence differs from capture")
    return [(outer,matrix,database)],None


def _unknown_capture_parts(reference: dict, root: Path) -> list:
    return _unknown_capture_inventory(reference,root)[0]


def _unknown_validated_observations(reference: dict, root: Path) -> tuple:
    parts,selections=_unknown_capture_inventory(reference,root)
    declared_ids=[run_id for _,matrix,_ in parts for run_id in _unknown_case_context(matrix)]
    _require(len(declared_ids) == len(set(declared_ids)),"unknown assembly reused one run for different variants")
    # Validate excluded raw observations too. Selection cannot hide a contradiction.
    observed=[(outer,matrix,database,case,_unknown_case(case,database,root,declared_runs=_unknown_case_context(matrix)))
              for outer,matrix,database in parts for case in matrix.get("caseResults",[])]
    if selections is None:
        _require(len({item[4]["name"] for item in observed}) == len(observed),"unknown matrix duplicated cases")
        return parts,observed,[]
    selected=[];excluded=[]
    available={(item[0]["captureId"],item[3]["name"]) for item in observed}
    _require(all((capture_id,name) in available for capture_id,names in selections.items() for name in names),"selected unknown observation was not supplied")
    for item in observed:
        if item[3]["name"] in selections[item[0]["captureId"]]:
            _require(item[4]["complete"],"selected unknown observation is incomplete")
            selected.append(item)
        else:
            _require(not item[4]["complete"],"unknown assembly excluded a completed observation")
            excluded.append(item)
    names=[item[3]["name"] for item in selected];runs=[item[3]["runId"] for item in selected]
    _require(len(names) == len(set(names)) == len(UNKNOWN_CASES) and set(names) == UNKNOWN_CASES,
             "unknown assembly must select exactly five unique complete variants")
    _require(len(runs) == len(set(runs)),"unknown assembly duplicated selected run")
    return parts,selected,excluded


def verify_unknown_matrix(reference: dict, *, repository_root: Path | None = None) -> dict:
    root = repository_root or Path(__file__).resolve().parents[3]
    parts,selected,excluded=_unknown_validated_observations(reference,root)
    results=[item[4] for item in selected]
    complete = {r["name"] for r in results if r["complete"]}
    facts = {name:False for name in UNKNOWN_FACTS}
    # Every advertised fact is derived from actual case rows and immutable files.
    if complete == UNKNOWN_CASES:
        composite = {"recovery_success_or_exhaustion","cancel_recovery_race"}
        for fact in set(UNKNOWN_FACTS)-composite:
            _require(all(fact in r["facts"] and type(r["facts"][fact]) is bool for r in results), "unknown case omitted an approved observation")
            facts[fact] = all(r["facts"][fact] for r in results)
        facts["recovery_success_or_exhaustion"] = True
        facts["cancel_recovery_race"] = True
    return {"facts":facts,"cases":results,"databaseNames":[p[2] for p in parts],"captureStatus":[p[1].get("status") for p in parts],
            "selectedObservations":[{"captureId":item[0]["captureId"],"caseName":item[3]["name"],"runId":item[3].get("runId")} for item in selected],
            "excludedIncompleteObservations":[{"captureId":item[0]["captureId"],"databaseName":item[2],"observation":item[4]} for item in excluded],
            "missingVariants":sorted(UNKNOWN_CASES-complete),"fullScenarioAcceptance":"passed" if all(facts.values()) else "blocked"}
