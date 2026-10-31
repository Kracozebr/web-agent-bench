"""Adversarial actual H1 copies; unit checks do not qualify producer source inventories."""
import hashlib
import json
import os
import tempfile
from copy import deepcopy
from pathlib import Path

import pytest

from tests.bdd.adapters.ber_h1_replay import _case, _ledger_authority, verify_h1_matrix
from tests.bdd.adapters.ber_recovery_replay import read_reference

ROOT = Path(__file__).resolve().parents[3]


def _fixture_entry(document, variant):
    if document.get("schemaVersion") == "ber-h1-cutoff-matrix-assembly/v1":
        selected = [p for p in document["captures"] if variant in document["selections"][p["sha256"]]]
        assert len(selected) == 1
        document = read_reference(ROOT, selected[0])
    entry = next(c for c in document["result"]["cases"] if c["variant"] == variant)
    return document, entry


@pytest.fixture
def actual_refunded_owner():
    path, sha = os.environ.get("BER_H1_MATRIX_PATH"), os.environ.get("BER_H1_MATRIX_SHA256")
    if path and sha:
        outer = read_reference(ROOT, {"path": path, "sha256": sha})
        _, entry = _fixture_entry(outer, "worker_restart_delivered")
        body = read_reference(ROOT, entry["reference"])
    else:
        path, sha = os.environ.get("BER_H1_REFUND_CASE_PATH"), os.environ.get("BER_H1_REFUND_CASE_SHA256")
        if not path or not sha: pytest.skip("exact actual refunded H1 case path/hash required")
        body = read_reference(ROOT, {"path": path, "sha256": sha})
    assert body["owner"]["result"]["refunds"]
    return body["owner"]["result"]


@pytest.mark.parametrize("mutation", [None, "refund_reserved_creation", "refund_negative_available", "refund_foreign_grant",
                                     "refund_foreign_operation", "refund_extra_entry"])
def test_actual_refund_ledger_preserves_original_source_and_balance_deltas(actual_refunded_owner, mutation):
    owner = deepcopy(actual_refunded_owner)
    refund = next(row for row in owner["ledger"] if row["entry_type"] == "refund")
    if mutation is None:
        _ledger_authority(owner)
        return
    if mutation == "refund_reserved_creation": refund["reserved_delta_units"] = "1"
    elif mutation == "refund_negative_available":
        refund["available_delta_units"], refund["expired_delta_units"] = "-1", "250001"
    elif mutation == "refund_foreign_grant": refund["bonus_grant_id"] = "00000000-0000-4000-8000-000000000000"
    elif mutation == "refund_foreign_operation": refund["operation_id"] = "runref_" + "0" * 32
    else:
        extra = deepcopy(refund)
        extra["id"] = "00000000-0000-4000-8000-000000000000"
        owner["ledger"].append(extra)
    with pytest.raises(AssertionError): _ledger_authority(owner)


@pytest.fixture
def actual_h1():
    path, sha = os.environ.get("BER_H1_MATRIX_PATH"), os.environ.get("BER_H1_MATRIX_SHA256")
    if not path or not sha:
        case_path, case_sha = os.environ.get("BER_H1_CASE_PATH"), os.environ.get("BER_H1_CASE_SHA256")
        if not case_path or not case_sha:
            pytest.skip("exact actual H1 matrix or case path/hash required")
        case_ref = {"path": case_path, "sha256": case_sha}
        case = read_reference(ROOT, case_ref)
        assert case["variant"] == "before_cutoff_dispatch_after"
        return None, case["owner"]["identity"]["database_name"], {**case, "reference": case_ref}
    reference = {"path": path, "sha256": sha}
    outer = read_reference(ROOT, reference)
    outer, entry = _fixture_entry(outer, "before_cutoff_dispatch_after")
    database = outer["provenance"]["databaseIsolation"]["databaseName"]
    return reference, database, entry


def test_actual_h1_cutoff_has_one_payment_and_exact_generation_fence(actual_h1):
    reference, database, entry = actual_h1
    result = _case(entry, database, ROOT)
    assert result["complete"] and result["payments"] == 3 and result["liveSlots"] == 0
    if reference is not None:
        matrix = verify_h1_matrix(reference, repository_root=ROOT)
        assert any(c["variant"] == entry["variant"] and c["complete"] for c in matrix["cases"])
        # Other unexercised variants cannot become passing through this positive subset.
        assert (matrix["fullScenarioAcceptance"] == "passed") == (not matrix["missingVariants"])


@pytest.mark.parametrize("mutation", ["foreign_generation", "duplicate_payment", "changed_cutoff", "invented_refund",
                                     "signed_challenge", "repeated_signed_wire", "duplicate_event_sequence",
                                     "debit_balance_creation", "reserve_balance_creation", "foreign_debit_grant",
                                     "foreign_debit_operation", "duplicate_ledger_identity", "extra_release", "all_ledger_foreign_grant", "future_funding"])
def test_recomputed_copy_hash_cannot_authorize_wrong_h1_effect_or_refund(actual_h1, mutation):
    _, database, original = actual_h1
    entry = deepcopy(original)
    body = read_reference(ROOT, entry["reference"])
    if mutation == "foreign_generation":
        body["bef"]["payments"][0]["generation_id"] = "00000000-0000-4000-8000-000000000000"
    elif mutation == "duplicate_payment":
        body["bef"]["payments"].append(deepcopy(body["bef"]["payments"][0]))
    elif mutation == "changed_cutoff":
        body["owner"]["result"]["closures"][0]["action_cutoff_sequence"] = "999"
    elif mutation == "invented_refund":
        body["owner"]["result"]["refunds"] = [{"evidence_hash": "0" * 64, "bonus_refunded_units": "250000"}]
    elif mutation == "future_funding":
        next(e for e in body["owner"]["result"]["events"] if e["event_type"] == "run.accepted")["created_at"] = "2000-01-01T00:00:00.000Z"
    elif mutation == "all_ledger_foreign_grant":
        for row in body["owner"]["result"]["ledger"]:
            row["bonus_grant_id"] = "00000000-0000-4000-8000-000000000000"
    elif mutation == "duplicate_event_sequence":
        body["owner"]["result"]["events"][1]["sequence"] = body["owner"]["result"]["events"][0]["sequence"]
    elif mutation in {"debit_balance_creation", "reserve_balance_creation", "foreign_debit_grant",
                      "foreign_debit_operation", "duplicate_ledger_identity", "extra_release"}:
        ledger = body["owner"]["result"]["ledger"]
        debit = next(r for r in ledger if r["entry_type"] == "debit")
        reserve = next(r for r in ledger if r["entry_type"] == "reserve")
        if mutation == "debit_balance_creation": debit["available_delta_units"] = "1"
        elif mutation == "reserve_balance_creation": reserve["reserved_delta_units"] = "250001"
        elif mutation == "foreign_debit_grant": debit["bonus_grant_id"] = "00000000-0000-4000-8000-000000000000"
        elif mutation == "foreign_debit_operation": debit["operation_id"] = "rundeb_" + "0" * 32
        elif mutation == "duplicate_ledger_identity": debit["id"] = reserve["id"]
        else:
            release = deepcopy(reserve)
            release.update(id="00000000-0000-4000-8000-000000000000", entry_type="release")
            ledger.append(release)
    else:
        action = next(a for a in body["owner"]["result"]["actions"]
                      if a["operation_id"] == body["fault"]["target"]["operationId"])
        traces = [r for r in body["proxy"]["actionRequests"] if r["actionId"] == action["id"]]
        if mutation == "signed_challenge":
            traces[0]["paymentProofPresent"] = True
        else:
            extra = deepcopy(traces[1])
            extra["ordinal"] = 3
            body["proxy"]["actionRequests"].append(extra)
            next(r for r in body["proxy"]["submissions"] if r["actionId"] == action["id"])["count"] = 3
    # Claims are deliberately green; only the independent raw binding may decide.
    body["status"] = "verified"
    body["checks"] = {key: True for key in body["checks"]}
    with tempfile.TemporaryDirectory(prefix="ber-h1-negative-", dir=ROOT / ".local") as folder:
        path = Path(folder) / "case.json"
        data = (json.dumps(body, ensure_ascii=False) + "\n").encode()
        path.write_bytes(data)
        entry = {**body, "reference": {"path": path.relative_to(ROOT).as_posix(),
                                      "sha256": hashlib.sha256(data).hexdigest()}}
        if "proxyReusable" in original:
            entry["proxyReusable"] = original["proxyReusable"]
        with pytest.raises(AssertionError):
            _case(entry, database, ROOT)


@pytest.mark.parametrize("mutation", ["duplicate_selection", "omitted_incomplete", "source_divergence", "parent_deleted_incomplete", "foreign_execution_profile"])
def test_actual_h1_assembly_cannot_hide_failed_or_divergent_parent(mutation):
    path, sha = os.environ.get("BER_H1_MATRIX_PATH"), os.environ.get("BER_H1_MATRIX_SHA256")
    if not path or not sha:
        pytest.skip("exact actual H1 assembly path/hash required")
    original = read_reference(ROOT, {"path": path, "sha256": sha})
    if original.get("schemaVersion") != "ber-h1-cutoff-matrix-assembly/v1":
        pytest.skip("actual H1 multi-parent assembly required for assembly negatives")
    document = deepcopy(original)
    with tempfile.TemporaryDirectory(prefix="ber-h1-assembly-negative-", dir=ROOT / ".local") as folder:
        def save(body, name):
            target = Path(folder) / name
            data = (json.dumps(body, ensure_ascii=False) + "\n").encode()
            target.write_bytes(data)
            return {"path": target.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(data).hexdigest()}
        if mutation == "duplicate_selection":
            names = next(iter(document["selections"].values()))
            names.append(names[0])
        elif mutation == "omitted_incomplete":
            if not document["excludedIncomplete"]:
                pytest.skip("actual excluded incomplete H1 observation required")
            document["excludedIncomplete"].pop()
        else:
            if mutation == "parent_deleted_incomplete":
                if not document["excludedIncomplete"]:
                    pytest.skip("actual excluded incomplete H1 observation required")
                omitted = document["excludedIncomplete"].pop()
                pointer = next(p for p in document["captures"] if p["sha256"] == omitted["captureSha256"])
            else:
                pointer = document["captures"][0]
            parent = deepcopy(read_reference(ROOT, pointer))
            if mutation == "parent_deleted_incomplete":
                parent["result"]["cases"] = [e for e in parent["result"]["cases"] if e["variant"] != omitted["variant"]]
            elif mutation == "foreign_execution_profile":
                entry = next(e for e in parent["result"]["cases"] if e.get("fault", {}).get("target"))
                body = deepcopy(read_reference(ROOT, entry["reference"]))
                body["owner"]["result"]["preparation"][0]["case_hash"] = "0" * 64
                old_reference = entry["reference"]
                new_reference = save(body, "case.json")
                entry.update(body)
                entry["reference"] = new_reference
                transport = deepcopy(read_reference(ROOT, parent["result"]["transportDiagnostics"]))
                next(e for e in transport["cases"] if e["reference"] == old_reference)["reference"] = new_reference
                parent["result"]["transportDiagnostics"] = save(transport, "transport.json")
            else:
                key = next(iter(parent["provenance"]["inputHashesBefore"]))
                for name in ("inputHashesBefore", "inputHashesAfter"):
                    parent["provenance"][name][key] = "0" * 64
            replacement = save(parent, "parent.json")
            document["captures"][document["captures"].index(pointer)] = replacement
            document["selections"][replacement["sha256"]] = document["selections"].pop(pointer["sha256"])
            for excluded in document["excludedIncomplete"]:
                if excluded["captureSha256"] == pointer["sha256"]:
                    excluded["captureSha256"] = replacement["sha256"]
        with pytest.raises(AssertionError):
            verify_h1_matrix(save(document, "assembly.json"), repository_root=ROOT)
