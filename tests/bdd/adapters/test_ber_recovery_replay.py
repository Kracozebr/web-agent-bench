"""Real retained-history replay negatives; opt in with the exact raw capture pin."""
import hashlib
import json
import os
import tempfile
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.bdd.adapters.ber_recovery_replay import canonical, digest, read_reference, verify_database_window, verify_native_recovery_history
from tools.replay_ber_recovery import run

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def actual_unknown_selection_source():
    from tests.bdd.adapters.ber_recovery_replay import verify_unknown_matrix
    path=os.environ.get("BER_UNKNOWN_SELECTION_PATH") or os.environ.get("BER_UNKNOWN_MATRIX_PATH")
    sha=os.environ.get("BER_UNKNOWN_SELECTION_SHA256") or os.environ.get("BER_UNKNOWN_MATRIX_SHA256")
    if not path or not sha: pytest.skip("exact current unknown selection capture path/hash required")
    ref={"path":path,"sha256":sha};result=verify_unknown_matrix(ref,repository_root=ROOT)
    assert next(case for case in result["cases"] if case["name"] == "conflicting_recover")["complete"]
    outer=read_reference(ROOT,ref,unknown_matrix_document=True)
    assert outer["schemaVersion"] == "ber-unknown-grading-capture/v1"
    assert any(case["name"] == "missing_recover" for case in result["cases"])
    return ref,outer


@pytest.mark.parametrize("mutation",["duplicate_selection","selected_incomplete","corrupted_excluded_raw"])
def test_actual_unknown_assembly_selection_cannot_hide_incomplete_or_contradictory_observations(actual_unknown_selection_source,mutation):
    from tests.bdd.adapters.ber_recovery_replay import verify_unknown_matrix
    original_ref,outer=actual_unknown_selection_source;ref=original_ref
    with tempfile.TemporaryDirectory(prefix="ber-assembly-negative-",dir=ROOT/".local") as temporary:
        folder=Path(temporary).resolve(strict=True)
        assert folder.parent == (ROOT/".local").resolve(strict=True)
        def save(name,value):
            data=(json.dumps(value,separators=(",",":"))+"\n").encode();path=folder/name;path.write_bytes(data)
            return {"path":path.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(data).hexdigest()}
        matrix=read_reference(ROOT,outer["result"]["evidence"],unknown_matrix_document=True)
        names=[case["name"] for case in matrix["caseResults"] if case["name"] != "missing_recover"]
        reason="unknown run identity differs"
        if mutation == "duplicate_selection": names.append(names[0]);reason="duplicated or invalid case selection"
        else:
            outer=deepcopy(outer)
            candidate=next(case for case in matrix["caseResults"] if case["name"] == "conflicting_recover")
            excluded=next(case for case in matrix["caseResults"] if case["name"] == "missing_recover")
            if mutation == "selected_incomplete":
                # A deliberate incomplete COPY of current-source rows, never a runtime observation.
                excluded["checkpoints"]=[checkpoint for checkpoint in excluded["checkpoints"] if checkpoint["phase"] != "candidate_unknown"]
                names.append("missing_recover");reason="selected unknown observation is incomplete"
            else:
                excluded["checkpoints"]=[deepcopy(next(checkpoint for checkpoint in candidate["checkpoints"] if checkpoint["phase"] == "candidate_unknown"))]
            excluded["status"]="verified"
            matrix_ref=save("matrix.json",matrix);outer["result"]={**matrix,"evidence":matrix_ref};ref=save("outer.json",outer)
        assembly=save("assembly.json",{"schemaVersion":"ber-unknown-grading-matrix-assembly/v1","captures":[ref],"selections":{ref["sha256"]:names}})
        with pytest.raises(AssertionError,match=reason): verify_unknown_matrix(assembly,repository_root=ROOT)


@pytest.fixture
def actual_completion_handoff():
    from tests.bdd.adapters.ber_recovery_replay import verify_completion_handoff
    path,sha=os.environ.get("BER_COMPLETION_HANDOFF_PATH"),os.environ.get("BER_COMPLETION_HANDOFF_SHA256")
    if not path or not sha: pytest.skip("exact actual first completion interruption path/hash required")
    ref={"path":path,"sha256":sha}
    result=verify_completion_handoff(ref,repository_root=ROOT)
    assert result["facts"] == {"restart_at_completion_handoff":True}
    return read_reference(ROOT,ref)


@pytest.mark.parametrize("mutation",["missing_admission_version","changed_rehashed_admission_version","handoff_before_crash",
                                      "writer_survives_stop","duplicate_handoff","changed_money"])
def test_actual_first_completion_copies_reject_broken_commit_and_rollback_invariants(actual_completion_handoff,mutation):
    from tests.bdd.adapters.ber_recovery_replay import verify_completion_handoff
    capture=deepcopy(actual_completion_handoff)
    phase="beforeCrash" if mutation in {"missing_admission_version","handoff_before_crash"} else "resumed" if mutation == "duplicate_handoff" else "afterStop"
    state=read_reference(ROOT,capture["checkpoints"][phase])
    if mutation == "missing_admission_version": state["rows"]["versions"].clear()
    elif mutation == "changed_rehashed_admission_version":
        version=state["rows"]["versions"][0];version["snapshot_json"]["profileRevision"]+=1
        version["snapshot_hash"]=digest(version["snapshot_json"])
    elif mutation == "handoff_before_crash":
        resumed=read_reference(ROOT,capture["checkpoints"]["resumed"])
        state["rows"]["handoffs"]=resumed["rows"]["handoffs"]
        state["rows"]["results"]=resumed["rows"]["results"]
    elif mutation == "writer_survives_stop":
        before=read_reference(ROOT,capture["checkpoints"]["beforeCrash"])
        state["locks"].extend(lock for lock in before["locks"] if lock["pid"] == capture["blockedPid"])
    elif mutation == "duplicate_handoff": state["rows"]["handoffs"].append(deepcopy(state["rows"]["handoffs"][0]))
    else: state["rows"]["ledger"][0]["amount_units"]=str(int(state["rows"]["ledger"][0]["amount_units"])+1)
    with tempfile.TemporaryDirectory(prefix="ber-completion-negative-",dir=ROOT/".local") as temporary:
        folder=Path(temporary).resolve(strict=True)
        assert folder.parent == (ROOT/".local").resolve(strict=True)
        data=(json.dumps(state,separators=(",",":"))+"\n").encode();state_path=folder/"checkpoint.json";state_path.write_bytes(data)
        capture["checkpoints"][phase]={"path":state_path.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(data).hexdigest()}
        capture["status"]="verified_subset"
        data=(json.dumps(capture,separators=(",",":"))+"\n").encode();capture_path=folder/"capture.json";capture_path.write_bytes(data)
        with pytest.raises(AssertionError):
            verify_completion_handoff({"path":capture_path.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(data).hexdigest()},repository_root=ROOT)


@pytest.fixture
def actual_first_refund():
    from tests.bdd.adapters.ber_recovery_replay import verify_fault_core
    path,sha=os.environ.get("BER_FAULT_CORE_PATH"),os.environ.get("BER_FAULT_CORE_SHA256")
    if not path or not sha: pytest.skip("exact actual fault core path/hash required")
    ref={"path":path,"sha256":sha};core=verify_fault_core(ref,repository_root=ROOT)
    case=read_reference(ROOT,ref)["result"]["cases"]["recoveryDeadlineExhaustion"]
    return case,core["databaseName"]


def test_actual_first_refund_crash_and_once_only_resume(actual_first_refund):
    from tests.bdd.adapters.ber_recovery_replay import verify_first_refund_crash
    case,database=actual_first_refund
    result=verify_first_refund_crash(case["recovery"]["refundCrash"],database=database,action=case["action"],binding=case["binding"],repository_root=ROOT)
    assert result["facts"] == {"crash_before_first_authorized_refund_commit":True}


@pytest.mark.parametrize("mutation",["refund_before_crash","writer_survives_stop","refund_units_changed"])
def test_actual_refund_copied_raw_rows_cannot_hide_early_commit_missing_rollback_or_amount_change(actual_first_refund,mutation):
    from tests.bdd.adapters.ber_recovery_replay import verify_first_refund_crash
    case,database=actual_first_refund;proof=deepcopy(case["recovery"]["refundCrash"])
    stage={"refund_before_crash":"beforeCrash","writer_survives_stop":"afterStop","refund_units_changed":"afterFinalization"}[mutation]
    doc=read_reference(ROOT,proof[stage]);state=doc["observation"]
    if mutation == "refund_before_crash":
        state["refunds"]=read_reference(ROOT,proof["afterFinalization"])["observation"]["refunds"]
    elif mutation == "writer_survives_stop":
        before=read_reference(ROOT,proof["beforeCrash"])
        state["locks"].extend(l for l in before["observation"]["locks"] if not l["granted"] and l["mode"] == "RowExclusiveLock")
    else:
        state["refunds"][0]["bonus_refunded_units"]=str(int(state["refunds"][0]["bonus_refunded_units"])+1)
    with tempfile.TemporaryDirectory(prefix="ber-refund-copy-",dir=ROOT/".local") as temporary:
        path=Path(temporary)/"mutated-checkpoint.json";data=(json.dumps(doc,indent=2)+'\n').encode();path.write_bytes(data)
        proof[stage]={"path":path.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(data).hexdigest()}
        with pytest.raises(AssertionError):
            verify_first_refund_crash(proof,database=database,action=case["action"],binding=case["binding"],repository_root=ROOT)


@pytest.mark.parametrize("mutation",["duplicate_path","wrong_bytes"])
def test_training_source_array_cannot_hide_duplicates_or_byte_mismatch(mutation):
    from tests.bdd.adapters.ber_recovery_replay import _training_source_inventory
    path="tools/replay_ber_recovery.py";data=(ROOT/path).read_bytes()
    entry={"path":path,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)}
    assert _training_source_inventory([entry],ROOT) == {path:entry["sha256"]}
    entries=[entry,entry] if mutation == "duplicate_path" else [{**entry,"bytes":len(data)+1}]
    with pytest.raises(AssertionError): _training_source_inventory(entries,ROOT)


@pytest.fixture
def actual_unknown_case():
    path,sha=os.environ.get("BER_UNKNOWN_MATRIX_PATH"),os.environ.get("BER_UNKNOWN_MATRIX_SHA256")
    if not path or not sha:
        pytest.skip("exact actual unknown matrix path/hash required")
    from tests.bdd.adapters.ber_recovery_replay import _unknown_case_context,_unknown_validated_observations
    _,selected,_=_unknown_validated_observations({"path":path,"sha256":sha},ROOT)
    _,matrix,database,case,result=next(item for item in selected if item[3]["name"] == "missing_exhaust_restart")
    assert result["complete"]
    return case,database,_unknown_case_context(matrix)


def test_actual_unknown_restart_retains_original_bound_and_no_grade(actual_unknown_case):
    from tests.bdd.adapters.ber_recovery_replay import _unknown_case
    case,database,context=actual_unknown_case
    result=_unknown_case(case,database,ROOT,declared_runs=context)
    assert result["complete"] and not result["missing"]
    assert all(value is True for value in result["facts"].values())


@pytest.mark.parametrize("mutation",["declared_prior_context","undeclared_context","future_context","wrong_current_closure"])
def test_cumulative_fault_records_require_declared_prior_context_without_diluting_current_binding(actual_unknown_case,mutation):
    from tests.bdd.adapters.ber_recovery_replay import _unknown_case
    original,database,actual_context=actual_unknown_case;case=deepcopy(original)
    current=case["runId"];foreign="a1111111-1111-4111-8111-111111111111"
    context={run:{**item,"index":item["index"]+1} for run,item in actual_context.items()}
    context[foreign]={"name":"missing_recover","index":0}
    record=deepcopy(next(r for r in case["fault"]["interventions"] if r["runId"] == current));record["runId"]=foreign
    task=next(t for t in case["checkpoints"][0]["state"]["result"]["tasks"] if t["task_index"] == 8)
    clock=datetime.fromisoformat(task["closed_at"].replace("Z","+00:00"))-timedelta(seconds=1)
    record["firstObservedAt"]=record["lastObservedAt"]=clock.isoformat()
    case["fault"]["interventions"].append(record)
    if mutation == "declared_prior_context":
        # This exercises only contextual selection using a copied record; it is
        # not accepted as another real matrix case or as current-run authority.
        assert _unknown_case(case,database,ROOT,declared_runs=context)["complete"]
        return
    if mutation == "undeclared_context": del context[foreign]
    elif mutation == "future_context": context[foreign]["index"]=context[current]["index"]+1
    else: next(r for r in case["fault"]["interventions"] if r["runId"] == current)["closureId"]="b1111111-1111-4111-8111-111111111111"
    with pytest.raises(AssertionError): _unknown_case(case,database,ROOT,declared_runs=context)


@pytest.mark.parametrize("mutation",["early_cancellation","unrelated_platform_authority"])
def test_raw_unknown_history_rejects_early_or_unrelated_terminal_even_with_verified_flags(actual_unknown_case,mutation):
    from tests.bdd.adapters.ber_recovery_replay import _unknown_case
    original,database,context=actual_unknown_case
    case=deepcopy(original)
    final=next(c for c in case["checkpoints"] if c["phase"] == "exhausted")["state"]["result"]
    if mutation == "early_cancellation":
        task=next(t for t in final["tasks"] if t["task_index"] == 8)
        final["run"]["cancellation_requested_at"]=task["closed_at"]
    else:
        final["run"]["cancellation_reason"]="coordinator_platform_failure"
    case["status"]="verified"
    with pytest.raises(AssertionError,match="cancelled early or used an unrelated terminal reason"):
        _unknown_case(case,database,ROOT,declared_runs=context)


@pytest.fixture
def actual_ref():
    path, sha = os.environ.get("BER_REPLAY_HISTORY_PATH"), os.environ.get("BER_REPLAY_HISTORY_SHA256")
    if not path or not sha:
        pytest.skip("exact actual BER raw history path/hash required")
    return {"path":path,"sha256":sha}


def test_two_actual_replays_and_missing_tampered_copies(actual_ref):
    result = run(actual_ref,repository_root=ROOT)
    assert result["twoReplayOutputsEqual"] and result["filesystemInputsUnchanged"]
    assert all(v["status"] == "rejected" for v in result["negativeCopies"].values())
    reconstructed = result["reconstructedHistory"]
    assert reconstructed["fullScenarioAcceptance"] == "blocked"
    assert {(r["mode"],r["tasks"]) for r in reconstructed["runs"]} == {("training",3),("ranked",12)}
    assert reconstructed["missingVariants"]  # Actual clean history does not invent interrupted transitions.


@pytest.mark.parametrize("mutation",[None,"missing","duplicate","foreign_inner_binding","changed_rehashed_snapshot","late_origin"])
def test_original_admission_snapshot_is_preserved_in_copied_actual_rows(actual_ref,mutation):
    from tests.bdd.adapters.ber_recovery_replay import _validate_admission_versions
    packet=read_reference(ROOT,actual_ref)
    ranked=next(run for run in packet["runs"] if run["rows"]["run"][0]["mode"] == "ranked")
    state={"identity":{"observed_at":packet["observedAt"]},"rows":{"run":deepcopy(ranked["rows"]["run"]),"versions":deepcopy(ranked["rows"]["version"])}}
    states={"before":state,"after":deepcopy(state)};changed=states["after"]["rows"]["versions"]
    if mutation is None:
        _validate_admission_versions(states,ranked["runId"])
        return
    if mutation == "missing": changed.clear()
    elif mutation == "duplicate": changed.append(deepcopy(changed[0]))
    elif mutation == "foreign_inner_binding":
        changed[0]["snapshot_json"]["agentId"]="11111111-1111-4111-8111-111111111111"
        changed[0]["snapshot_hash"]=digest(changed[0]["snapshot_json"])
    elif mutation == "changed_rehashed_snapshot":
        changed[0]["snapshot_json"]["profileRevision"]+=1
        changed[0]["snapshot_hash"]=digest(changed[0]["snapshot_json"])
    else:
        started=datetime.fromisoformat(state["rows"]["run"][0]["started_at"].replace("Z","+00:00"))
        changed[0]["created_at"]=(started+timedelta(seconds=1)).isoformat()
    with pytest.raises(AssertionError): _validate_admission_versions(states,ranked["runId"])


@pytest.mark.parametrize("mutation",["action_operation", "evaluation_credit", "successor_predecessor"])
def test_recomputed_raw_row_hash_cannot_hide_broken_journal_binding(actual_ref,mutation):
    packet = read_reference(ROOT,actual_ref)
    rows = packet["runs"][1]["rows"]
    if mutation == "action_operation":
        rows["actions"][0]["operation_id"] = "forged_operation_id_123456"
        changed = "actions"
    elif mutation == "evaluation_credit":
        target = next(e for e in rows["evaluations"] if e["task_id"] == "S2")
        target["result_json"]["credit"]["numerator"] = "6"
        target["result_hash"] = digest(target["result_json"])
        changed = "evaluations"
    else:
        event = next(e for e in rows["events"] if e["event_type"] == "task.activated")
        event["payload_json"]["predecessorReceipt"]["inputHash"] = "0"*64
        event["payload_hash"] = digest(event["payload_json"])
        changed = "events"
    packet["runs"][1]["sets"][changed] = {"count":len(rows[changed]),"sha256":digest(sorted(rows[changed],key=canonical))}
    # Only the copied raw capture is written; its original file and all business files stay untouched.
    copy_path = ROOT/".local"/("ber-test-replay-"+mutation+"-"+str(os.getpid())+".json")
    assert copy_path.resolve().parent == (ROOT/".local").resolve()
    data = json.dumps(packet,separators=(",",":"),ensure_ascii=False).encode()
    try:
        with copy_path.open("xb") as file: file.write(data)
        with pytest.raises(AssertionError):
            verify_native_recovery_history({"path":copy_path.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(data).hexdigest()},repository_root=ROOT)
    finally:
        copy_path.unlink(missing_ok=True)


def test_evidence_reference_cannot_escape_declared_copy():
    with pytest.raises(AssertionError,match="unsafe"):
        read_reference(ROOT,{"path":"../outside.json","sha256":"0"*64})


@pytest.fixture
def bounded_document_root():
    with tempfile.TemporaryDirectory(prefix="ber-document-boundary-",dir=ROOT/".local") as temporary:
        folder=Path(temporary).resolve(strict=True)
        assert folder.parent == (ROOT/".local").resolve(strict=True)
        yield folder


def test_larger_unknown_document_allowance_keeps_raw_cap_and_hash_checks(bounded_document_root,monkeypatch):
    from tests.bdd.adapters import ber_recovery_replay as reader
    tmp_path=bounded_document_root
    # Scale only the byte limits; exercise actual files, SHA binding and JSON schema.
    monkeypatch.setattr(reader,"MAX_REFERENCE_BYTES",128)
    monkeypatch.setattr(reader,"MAX_UNKNOWN_MATRIX_BYTES",512)
    value={"schemaVersion":"ber-unknown-grading-capture/v1","padding":"x"*180}
    data=json.dumps(value).encode();(tmp_path/"matrix.json").write_bytes(data)
    ref={"path":"matrix.json","sha256":hashlib.sha256(data).hexdigest()}
    with pytest.raises(AssertionError,match="bounded document size"):
        read_reference(tmp_path,ref)
    assert read_reference(tmp_path,ref,unknown_matrix_document=True) == value
    with pytest.raises(AssertionError,match="hash mismatch"):
        read_reference(tmp_path,{**ref,"sha256":"0"*64},unknown_matrix_document=True)
    with pytest.raises(AssertionError,match="typed JSON"):
        read_reference(tmp_path,ref,json_body=False,unknown_matrix_document=True)
    (tmp_path/"matrix.json").write_bytes(json.dumps({**value,"padding":"x"*600}).encode())
    with pytest.raises(AssertionError,match="bounded document size"):
        read_reference(tmp_path,ref,unknown_matrix_document=True)


def test_larger_unknown_allowance_does_not_admit_business_document(bounded_document_root,monkeypatch):
    from tests.bdd.adapters import ber_recovery_replay as reader
    tmp_path=bounded_document_root
    monkeypatch.setattr(reader,"MAX_REFERENCE_BYTES",128)
    monkeypatch.setattr(reader,"MAX_UNKNOWN_MATRIX_BYTES",512)
    data=json.dumps({"schemaVersion":"ber-independent-recovery-history/v1","padding":"x"*180}).encode()
    (tmp_path/"business.json").write_bytes(data)
    with pytest.raises(AssertionError,match="restricted to unknown matrix"):
        read_reference(tmp_path,{"path":"business.json","sha256":hashlib.sha256(data).hexdigest()},unknown_matrix_document=True)


def test_integer_canonical_boundary_refuses_ambiguous_float():
    with pytest.raises(AssertionError,match="floating"):
        canonical({"credit":0.1})


def test_true_producer_flags_cannot_replace_two_actual_replay_outputs(actual_ref):
    original = read_reference(ROOT,actual_ref)
    start = datetime.now(timezone.utc)
    fingerprint = {"schemaVersion":original["schemaVersion"],"mode":"fingerprint","databaseName":original["databaseName"],
                   "observer":original["observer"],"sourceHashes":original["sourceHashes"],"sourceHashesAfter":original["sourceHashesAfter"],
                   "runs":[{"runId":r["runId"],"sets":r["sets"]} for r in original["runs"]]}
    report = {"schemaVersion":"ber-independent-two-replay-report/v1","capture":actual_ref,"passes":[],
              "startedAt":(start+timedelta(seconds=1)).isoformat(),"finishedAt":(start+timedelta(seconds=2)).isoformat(),
              "twoReplayOutputsEqual":True,"filesystemInputsUnchanged":True}
    with tempfile.TemporaryDirectory(prefix="ber-replay-flags-test-",dir=ROOT/".local") as temporary:
        folder=Path(temporary).resolve()
        assert folder.parent == (ROOT/".local").resolve()
        refs=[]
        for name,at in [("before",start),("after",start+timedelta(seconds=3))]:
            value={**fingerprint,"observedAt":at.isoformat()}
            path=folder/(name+".json"); data=json.dumps(value).encode();path.write_bytes(data)
            refs.append({"path":path.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(data).hexdigest()})
        with pytest.raises(AssertionError,match="two actual replay outputs"):
            verify_database_window(*refs,report,repository_root=ROOT)
