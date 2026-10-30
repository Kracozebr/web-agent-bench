"""Fail-closed BRL evidence adapter for the approved 25-scenario delta.

Only BRL-SC-023/024 raw HTTP/MCP/PostgreSQL records and BRL-SC-025 raw Codex,
browser, and child launch captures have scenario-specific verifiers. The adapter
replays hash-pinned generic-writer bundles, recomputes every claim, and leaves
blocked or incomplete evidence blocked. Other approved BRL scenarios remain
unpassable until their boundary verifiers exist.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from tests.bdd.adapters import ScenarioContext, ScenarioRegistry
from tests.bdd.adapters.benchmark_run_lifecycle_verifier import derive_observations

CHANGE_NAME = "benchmark-run-lifecycle"
SCENARIO_IDS = tuple(f"BRL-SC-{number:03d}" for number in range(1, 26))
ADAPTER_PROFILES = frozenset({"benchmark_run_lifecycle_http_adapter", "benchmark_launch_browser_client_adapter"})
PASSABLE_SCENARIOS: frozenset[str] = frozenset({"BRL-SC-023", "BRL-SC-024", "BRL-SC-025"})
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = REPOSITORY_ROOT / "artifacts" / "runs" / "acceptance"
CHANGE_ROOT = REPOSITORY_ROOT / "openspec" / "changes" / CHANGE_NAME
PROPOSAL_PATH = CHANGE_ROOT / "bdd-harness-proposal.json"
CONTRACT_PATH = REPOSITORY_ROOT / "tests" / "bdd" / "changes" / CHANGE_NAME / "harness-contracts.json"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}\.json$")
SECRET_KEY_RE = re.compile(
    r"^(?:accesstoken|authtoken|bearer|cookie|cookies|password|secret|clientsecret|"
    r"manualtoken|tokenvalue|authorization|privatekey|mnemonic|seedphrase|rawsignature|"
    r"signature|walletmaterial|databaseurl|rpcurl|oauthcode|oauthstate)$",
    re.IGNORECASE,
)
SECRET_TEXT_RE = re.compile(
    r"\bBearer\s+(?!<redacted>|\[redacted\]|\*{3})\S+|"
    r"(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)"
    r"(?!<redacted>|\[redacted\])[^&#\s]+|"
    r"\b(?:aap1|oid1|oat1)_[A-Za-z0-9_-]{32,}\b|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    re.IGNORECASE,
)


def _assert_secret_free(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key), flags=re.IGNORECASE)
            if SECRET_KEY_RE.fullmatch(normalized):
                raise AssertionError(f"credential-bearing evidence field at {path}.{key}")
            _assert_secret_free(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_TEXT_RE.search(value):
        raise AssertionError(f"credential-like evidence text at {path}")


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"Expected a JSON object in {path.name}")
    _assert_secret_free(value, path.name)
    return value


def _load_contract_sources() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    proposal_bytes = PROPOSAL_PATH.read_bytes()
    contract_bytes = CONTRACT_PATH.read_bytes()
    proposal = json.loads(proposal_bytes.decode("utf-8"))
    contract = json.loads(contract_bytes.decode("utf-8"))
    expected = set(SCENARIO_IDS)
    proposal_rows = proposal.get("protected_scenarios") if isinstance(proposal, dict) else None
    contract_rows = contract.get("protected_scenarios") if isinstance(contract, dict) else None
    if (
        proposal.get("proposal_schema") != "bdd-harness-contract-proposal/v1"
        or proposal.get("review_status") != "approved"
        or not isinstance(proposal_rows, dict)
        or set(proposal_rows) != expected
        or not isinstance(contract_rows, dict)
        or set(contract_rows) != expected
        or contract.get("coverage_policy", {}).get("required_protected_scenarios") != list(SCENARIO_IDS)
        or contract.get("coverage_policy", {}).get("status") != "complete"
    ):
        raise AssertionError("BRL approved and runtime contract inventories are incomplete or inconsistent")
    for scenario_id in SCENARIO_IDS:
        approved = proposal_rows[scenario_id]
        runtime = contract_rows[scenario_id]
        for proposal_key, contract_key in (
            ("boundary", "boundary"),
            ("required_observations", "required_observations"),
            ("negative_variants", "negative_variants"),
            ("durable_effects", "durable_effects"),
        ):
            if approved.get(proposal_key) != runtime.get(contract_key):
                raise AssertionError(f"{scenario_id} approved/runtime {proposal_key} inventory drifted")
        if approved.get("mandatory") is not True or approved.get("gate") != "environment":
            raise AssertionError(f"{scenario_id} is not the approved mandatory environment gate")
        if approved.get("adapter") not in ADAPTER_PROFILES:
            raise AssertionError(f"{scenario_id} uses an unregistered BRL adapter profile")
    if {proposal_rows[scenario_id]["adapter"] for scenario_id in SCENARIO_IDS} != ADAPTER_PROFILES:
        raise AssertionError("BRL adapter profile inventory drifted")
    return proposal, contract, contract_bytes


def _inside(root: Path, path: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved_root not in resolved.parents:
        raise AssertionError("BRL evidence path escapes its declared root")
    return resolved


# AICODE-NOTE: Node producers do not execute these Python readers. Their historical
# hashes remain in the identical before/after inventory; run_bdd_acceptance pins
# the present reader separately. Producer, policy and normative inputs must still
# match current bytes, so a reader fix cannot authorize stale product behavior.
_REPLAY_READER_SOURCES = frozenset({
    "tests/bdd/adapters/benchmark_task_suite.py",
    "tests/bdd/adapters/benchmark_run_lifecycle.py",
    "tests/bdd/adapters/benchmark_run_lifecycle_verifier.py",
    "tests/bdd/adapters/benchmark_run_lifecycle_codex_verifier.py",
    "tests/bdd/adapters/test_benchmark_task_suite.py",
    "tests/bdd/adapters/test_benchmark_run_lifecycle_verifier.py",
    "tests/bdd/adapters/test_benchmark_run_lifecycle_codex_verifier.py",
    "tests/bdd/adapters/test_benchmark_run_lifecycle_adapter_bundle.py",
})

def _verify_source_inventory(provenance: dict[str, Any], scenario_id: str) -> None:
    before = provenance.get("inputHashesBefore")
    after = provenance.get("inputHashesAfter")
    if (
        provenance.get("sourceStableDuringRun") is not True
        or not isinstance(before, dict)
        or not before
        or before != after
    ):
        raise AssertionError(f"{scenario_id} provenance lacks identical before/after source inventories")
    for relative, expected in before.items():
        if (
            not isinstance(relative, str)
            or "\\" in relative
            or ":" in relative
            or Path(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
            or not isinstance(expected, str)
            or not SHA256_RE.fullmatch(expected)
        ):
            raise AssertionError(f"{scenario_id} provenance contains an unsafe source inventory entry")
        source = _inside(REPOSITORY_ROOT, REPOSITORY_ROOT.joinpath(*PurePosixPath(relative).parts))
        if relative in _REPLAY_READER_SOURCES:
            continue
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected.lower():
            raise AssertionError(f"{scenario_id} captured source no longer matches {relative}")


def _load_run(scenario_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]] | None:
    if scenario_id not in SCENARIO_IDS:
        raise ValueError(f"Unsupported BRL scenario identity: {scenario_id}")
    scenario_root = EVIDENCE_ROOT / scenario_id
    index_path = scenario_root / "manifest.json"
    if not index_path.is_file():
        return None
    index = _read_object(index_path)
    if (
        index.get("schemaVersion") != "benchmark-run-lifecycle-evidence-index/v1"
        or index.get("scenarioId") != scenario_id
        or index.get("status") not in {"running", "blocked", "failed", "passed"}
    ):
        raise AssertionError(f"{scenario_id} evidence index identity or schema is invalid")
    run_id = index.get("latestRunId")
    runs = index.get("runs")
    if not isinstance(run_id, str) or not UUID_RE.fullmatch(run_id) or not isinstance(runs, list) or run_id not in runs:
        raise AssertionError(f"{scenario_id} evidence index does not bind its latest run")
    if index["status"] == "running":
        return {"status": "running", "blockedReasonCode": "capture_not_terminal"}, {}

    run_root = _inside(scenario_root, scenario_root / "runs" / run_id)
    manifest = _read_object(run_root / "manifest.json")
    if (
        manifest.get("schemaVersion") != "benchmark-run-lifecycle-acceptance/v1"
        or manifest.get("specProfile") != "active-delta"
        or manifest.get("scenarioId") != scenario_id
        or manifest.get("runId") != run_id
        or manifest.get("status") not in {"blocked", "failed", "passed"}
        or manifest.get("status") != index.get("status")
    ):
        raise AssertionError(f"{scenario_id} run manifest identity or status is invalid")

    _, contract, contract_bytes = _load_contract_sources()
    contract_row = contract["protected_scenarios"][scenario_id]
    inventory = manifest.get("artifacts")
    if not isinstance(inventory, list) or not inventory:
        raise AssertionError(f"{scenario_id} must inventory its raw evidence artifacts")
    loaded: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    for item in inventory:
        if not isinstance(item, dict):
            raise AssertionError(f"{scenario_id} artifact inventory contains a malformed row")
        relative = item.get("path")
        digest = item.get("sha256")
        if (
            not isinstance(relative, str)
            or not ARTIFACT_PATH_RE.fullmatch(relative)
            or "\\" in relative
            or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
            or relative in seen_paths
        ):
            raise AssertionError(f"{scenario_id} has an unsafe or duplicate artifact path")
        seen_paths.add(relative)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise AssertionError(f"{scenario_id} has an invalid artifact digest")
        if item.get("contentType") != "application/json" or not isinstance(item.get("boundary"), str) or not item["boundary"].strip():
            raise AssertionError(f"{scenario_id} artifact metadata is invalid")
        artifact_path = _inside(run_root, run_root.joinpath(*PurePosixPath(relative).parts))
        content = artifact_path.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise AssertionError(f"{scenario_id} artifact hash mismatch for {relative}")
        payload = json.loads(content.decode("utf-8"))
        if not isinstance(payload, dict):
            raise AssertionError(f"{scenario_id} artifact {relative} is not a JSON object")
        _assert_secret_free(payload, relative)
        loaded[relative] = payload

    provenance = loaded.get("provenance.json")
    if not isinstance(provenance, dict) or provenance.get("contractSha256") != hashlib.sha256(contract_bytes).hexdigest():
        raise AssertionError(f"{scenario_id} evidence is not bound to the current BRL runtime contract")
    if manifest.get("status") == "passed":
        _verify_source_inventory(provenance, scenario_id)
    required_observations = set(contract_row["required_observations"])
    required_negatives = set(contract_row["negative_variants"])
    observations = manifest.get("observations")
    negatives = manifest.get("negativeVariants")
    if not isinstance(observations, dict) or set(observations) != required_observations:
        raise AssertionError(f"{scenario_id} observation inventory drifted")
    if not isinstance(negatives, dict) or set(negatives) != required_negatives:
        raise AssertionError(f"{scenario_id} negative-variant inventory drifted")
    return manifest, loaded


def _blocked_gap(scenario_id: str, boundary_detail: str) -> str:
    if scenario_id == "BRL-SC-025":
        return "no hash-pinned BRL-SC-025 Codex, browser, and launch runtime bundle is available"
    if scenario_id in {"BRL-SC-005", "BRL-SC-006", "BRL-SC-012", "BRL-SC-013", "BRL-SC-019"}:
        return (
            f"no per-scenario {boundary_detail} HTTP evidence bundle; the existing run-start integration "
            "uses synthetic readiness/fence ports and is not accepted as this environment gate"
        )
    return f"no per-scenario hash-pinned {boundary_detail} runtime evidence bundle is available"


def _reject_unverified_pass(scenario_id: str) -> None:
    if scenario_id not in PASSABLE_SCENARIOS:
        raise AssertionError(
            f"{scenario_id} cannot pass from manifest status or fixture/unit-model claims; "
            "a scenario-compatible raw-boundary verifier is not implemented"
        )


class BenchmarkRunLifecycleEvidenceCase:
    """Replay only immutable environment-bound BRL captures; never mutate the app."""

    def __init__(self, scenario_id: str, proposal_row: dict[str, Any], contract_row: dict[str, Any]) -> None:
        self.scenario_id = scenario_id
        self.proposal_row = proposal_row
        self.contract_row = contract_row

    def setup(self, context: ScenarioContext) -> None:
        if context.scenario_id != self.scenario_id:
            raise AssertionError("BRL mapper and scenario identity differ")
        context.state["brl_boundary_detail"] = self.proposal_row["boundary_detail"]
        context.state["brl_evidence_root"] = EVIDENCE_ROOT.as_posix()

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        loaded = _load_run(self.scenario_id)
        if loaded is None:
            gap = _blocked_gap(self.scenario_id, self.proposal_row["boundary_detail"])
            pytest.skip(f"BLOCKED: {gap}")
        manifest, artifacts = loaded
        context.state["brl_manifest"] = manifest
        context.state["brl_artifacts"] = artifacts
        if manifest.get("status") == "running":
            pytest.skip("BLOCKED: BRL evidence capture is not terminal")
        if manifest.get("status") == "failed":
            raise AssertionError(f"{self.scenario_id} recorded a failed local runtime capture")
        if manifest.get("status") == "blocked":
            reason = manifest.get("blockedReasonCode")
            if not isinstance(reason, str) or not reason:
                raise AssertionError(f"{self.scenario_id} blocked capture lacks a reason code")
            observations = manifest["observations"]
            negatives = manifest["negativeVariants"]
            if any(not isinstance(row, dict) or row.get("status") != "not_run" for row in (*observations.values(), *negatives.values())):
                raise AssertionError(f"{self.scenario_id} blocked capture cannot promote unverified partial claims")
            pytest.skip(f"BLOCKED: {reason}")
        _reject_unverified_pass(self.scenario_id)

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        manifest = context.state.get("brl_manifest")
        if not isinstance(manifest, dict) or manifest.get("status") != "passed":
            raise AssertionError(f"{self.scenario_id} has no verified BRL pass candidate")
        _reject_unverified_pass(self.scenario_id)



class ExplicitBenchmarkRunLifecycleEvidenceCase(BenchmarkRunLifecycleEvidenceCase):
    """Explicit contract bindings; only independently derived runtime facts can pass."""

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        token = context.scenario_id.replace("-", "_")
        method = getattr(self, "_execute_" + token, None)
        if method is None:
            raise AssertionError("BRL scenario has no explicit execution binding")
        method(context, when_text)

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        token = context.scenario_id.replace("-", "_")
        method = getattr(self, "_verify_" + token, None)
        if method is None:
            raise AssertionError("BRL scenario has no explicit verification binding")
        method(context, then_text)

    def _execute_bound(self, context: ScenarioContext, scenario_id: str) -> None:
        if context.scenario_id != scenario_id or self.scenario_id != scenario_id:
            raise AssertionError("BRL scenario binding mismatch")
        if scenario_id not in PASSABLE_SCENARIOS:
            pytest.skip("BLOCKED: this approved BRL boundary has no scenario-specific live producer yet")
        loaded = _load_run(scenario_id)
        if loaded is None:
            pytest.skip("BLOCKED: no hash-pinned local HTTP/MCP/PostgreSQL runtime capture is available")
        manifest, artifacts = loaded
        if manifest.get("status") == "running":
            pytest.skip("BLOCKED: BRL runtime capture is not terminal")
        if manifest.get("status") == "blocked":
            reason = manifest.get("blockedReasonCode")
            pytest.skip("BLOCKED: " + (reason if isinstance(reason, str) and reason else "required live fixture coverage is absent"))
        if manifest.get("status") != "passed":
            raise AssertionError("BRL runtime capture did not claim a complete pass")
        raw = artifacts.get("runtime-evidence.json")
        if scenario_id == "BRL-SC-025":
            from tests.bdd.adapters.benchmark_run_lifecycle_codex_verifier import derive_observations as derive_codex_observations
            facts = derive_codex_observations(scenario_id, raw)
        else:
            facts = derive_observations(scenario_id, raw)
        if facts is None:
            raise AssertionError("BRL pass claim has no scenario-compatible raw HTTP/MCP/PostgreSQL evidence")
        names = (*self.contract_row["required_observations"], *self.contract_row["negative_variants"])
        if any(facts.get(name) is not True for name in names):
            raise AssertionError("BRL pass claim contains missing or false derived facts")
        _reject_unverified_pass(scenario_id)
        context.state["brl_verified_facts"] = facts
        context.state["brl_verified_scenario"] = scenario_id

    def _facts_for_verification(self, context: ScenarioContext, scenario_id: str) -> dict[str, bool]:
        _reject_unverified_pass(scenario_id)
        if context.scenario_id != scenario_id or context.state.get("brl_verified_scenario") != scenario_id:
            raise AssertionError("BRL facts were not derived from this scenario's runtime evidence")
        facts = context.state.get("brl_verified_facts")
        if not isinstance(facts, dict):
            raise AssertionError("BRL runtime verifier did not produce observation facts")
        return facts

    def _execute_BRL_SC_001(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-001")

    def _execute_BRL_SC_002(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-002")

    def _execute_BRL_SC_003(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-003")

    def _execute_BRL_SC_004(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-004")

    def _execute_BRL_SC_005(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-005")

    def _execute_BRL_SC_006(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-006")

    def _execute_BRL_SC_007(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-007")

    def _execute_BRL_SC_008(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-008")

    def _execute_BRL_SC_009(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-009")

    def _execute_BRL_SC_010(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-010")

    def _execute_BRL_SC_011(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-011")

    def _execute_BRL_SC_012(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-012")

    def _execute_BRL_SC_013(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-013")

    def _execute_BRL_SC_014(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-014")

    def _execute_BRL_SC_015(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-015")

    def _execute_BRL_SC_016(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-016")

    def _execute_BRL_SC_017(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-017")

    def _execute_BRL_SC_018(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-018")

    def _execute_BRL_SC_019(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-019")

    def _execute_BRL_SC_020(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-020")

    def _execute_BRL_SC_021(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-021")

    def _execute_BRL_SC_022(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-022")

    def _execute_BRL_SC_023(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-023")

    def _execute_BRL_SC_024(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-024")

    def _execute_BRL_SC_025(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        self._execute_bound(context, "BRL-SC-025")

    def _verify_BRL_SC_001(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-001")
        context.check("new_training_quote_over_6", facts.get("new_training_quote_over_6") is True)
        context.check("training_eligibility_s1_m1_h1", facts.get("training_eligibility_s1_m1_h1") is True)
        context.check("training_quote_over_6", facts.get("training_quote_over_6") is True)
        context.check("single_quotes_83334_166667_250000", facts.get("single_quotes_83334_166667_250000") is True)
        context.check("whole_request_rounding", facts.get("whole_request_rounding") is True)
        context.check("ranked_twelve_price_and_weights_unchanged", facts.get("ranked_twelve_price_and_weights_unchanged") is True)
        context.check("identity_snapshot", facts.get("identity_snapshot") is True)
        context.check("quoted_price_immutable", facts.get("quoted_price_immutable") is True)
        context.check("reservation_created", facts.get("reservation_created") is True)
        context.check("zero_price_retained", facts.get("zero_price_retained") is True)
        context.check("timer_not_started", facts.get("timer_not_started") is True)
        context.check("admitted_version_and_environment_immutable", facts.get("admitted_version_and_environment_immutable") is True)
        context.check("queued_old_version_remains_startable", facts.get("queued_old_version_remains_startable") is True)
        context.check("authenticated_existing_retry_not_new_admission", facts.get("authenticated_existing_retry_not_new_admission") is True)
        context.check("activation_alone_no_cancel_or_retarget", facts.get("activation_alone_no_cancel_or_retarget") is True)
        context.check("pinned_exposure", facts.get("pinned_exposure") is True)
        context.check("pinned_open_weight_denominator", facts.get("pinned_open_weight_denominator") is True)
        context.check("old_admission_snapshot_preserved", facts.get("old_admission_snapshot_preserved") is True)
        context.check("price_changes_after_queue", facts.get("price_changes_after_queue") is True)
        context.check("zero_becomes_paid", facts.get("zero_becomes_paid") is True)
        context.check("duplicate_training_selection", facts.get("duplicate_training_selection") is True)
        context.check("activation_after_queued_admission_before_start", facts.get("activation_after_queued_admission_before_start") is True)
        context.check("lost_response_retry_after_activation", facts.get("lost_response_retry_after_activation") is True)
        context.check("activation_during_preparation", facts.get("activation_during_preparation") is True)
        context.check("closed_training_selection", facts.get("closed_training_selection") is True)
        context.check("old_admission_not_repriced", facts.get("old_admission_not_repriced") is True)

    def _verify_BRL_SC_002(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-002")
        context.check("unauthorized_rejected", facts.get("unauthorized_rejected") is True)
        context.check("invalid_selection_rejected", facts.get("invalid_selection_rejected") is True)
        context.check("no_foreign_data", facts.get("no_foreign_data") is True)
        context.check("no_admission_effect", facts.get("no_admission_effect") is True)
        context.check("new_training_and_ranked_active_version_only", facts.get("new_training_and_ranked_active_version_only") is True)
        context.check("activation_and_admission_serialized", facts.get("activation_and_admission_serialized") is True)
        context.check("nonactive_version_no_hold_or_run", facts.get("nonactive_version_no_hold_or_run") is True)
        context.check("no_silent_target_version_change", facts.get("no_silent_target_version_change") is True)
        context.check("no_closed_payload_or_reservation", facts.get("no_closed_payload_or_reservation") is True)
        context.check("missing_token", facts.get("missing_token") is True)
        context.check("foreign_owner_agent", facts.get("foreign_owner_agent") is True)
        context.check("scope_missing", facts.get("scope_missing") is True)
        context.check("ranked_subset", facts.get("ranked_subset") is True)
        context.check("unknown_task", facts.get("unknown_task") is True)
        context.check("empty_or_duplicate_training_tasks", facts.get("empty_or_duplicate_training_tasks") is True)
        context.check("new_ranked_request_for_old_version", facts.get("new_ranked_request_for_old_version") is True)
        context.check("new_training_request_for_old_version", facts.get("new_training_request_for_old_version") is True)
        context.check("activation_wins_admission_race", facts.get("activation_wins_admission_race") is True)
        context.check("new_key_reuses_old_run_identity", facts.get("new_key_reuses_old_run_identity") is True)
        context.check("same_key_changed_version_conflict", facts.get("same_key_changed_version_conflict") is True)
        context.check("closed_training_id", facts.get("closed_training_id") is True)
        context.check("mixed_open_closed", facts.get("mixed_open_closed") is True)
        context.check("forged_exposure", facts.get("forged_exposure") is True)
        context.check("zero_price_closed_request", facts.get("zero_price_closed_request") is True)

    def _verify_BRL_SC_003(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-003")
        context.check("same_run_after_retry", facts.get("same_run_after_retry") is True)
        context.check("same_reservation_after_restart", facts.get("same_reservation_after_restart") is True)
        context.check("payload_conflict_rejected", facts.get("payload_conflict_rejected") is True)
        context.check("single_reservation", facts.get("single_reservation") is True)
        context.check("response_lost", facts.get("response_lost") is True)
        context.check("api_restart", facts.get("api_restart") is True)
        context.check("same_key_changed_payload", facts.get("same_key_changed_payload") is True)

    def _verify_BRL_SC_004(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-004")
        context.check("available_funds_nonnegative", facts.get("available_funds_nonnegative") is True)
        context.check("operation_cap_enforced", facts.get("operation_cap_enforced") is True)
        context.check("daily_cap_enforced", facts.get("daily_cap_enforced") is True)
        context.check("benchmark_cap_enforced", facts.get("benchmark_cap_enforced") is True)
        context.check("concurrent_reservations_serialized", facts.get("concurrent_reservations_serialized") is True)
        context.check("two_agents_one_balance", facts.get("two_agents_one_balance") is True)
        context.check("insufficient_owner_funds", facts.get("insufficient_owner_funds") is True)
        context.check("operation_cap_exceeded", facts.get("operation_cap_exceeded") is True)
        context.check("daily_cap_exhausted", facts.get("daily_cap_exhausted") is True)
        context.check("benchmark_cap_exhausted", facts.get("benchmark_cap_exhausted") is True)

    def _verify_BRL_SC_005(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-005")
        context.check("environment_ready_verified", facts.get("environment_ready_verified") is True)
        context.check("single_start_debit", facts.get("single_start_debit") is True)
        context.check("first_task_active_once", facts.get("first_task_active_once") is True)
        context.check("start_time_persisted", facts.get("start_time_persisted") is True)
        context.check("unready_not_charged", facts.get("unready_not_charged") is True)
        context.check("persisted_queue_deadline_checked_at_start", facts.get("persisted_queue_deadline_checked_at_start") is True)
        context.check("expired_unstarted_request_no_debit_or_activation", facts.get("expired_unstarted_request_no_debit_or_activation") is True)
        context.check("delayed_expiry_job_not_late_start_authority", facts.get("delayed_expiry_job_not_late_start_authority") is True)
        context.check("environment_not_ready", facts.get("environment_not_ready") is True)
        context.check("duplicate_start", facts.get("duplicate_start") is True)
        context.check("restart_after_start_commit", facts.get("restart_after_start_commit") is True)
        context.check("start_before_queue_deadline", facts.get("start_before_queue_deadline") is True)
        context.check("start_exactly_at_queue_deadline", facts.get("start_exactly_at_queue_deadline") is True)
        context.check("start_after_deadline_before_expiry_worker", facts.get("start_after_deadline_before_expiry_worker") is True)
        context.check("restart_past_deadline", facts.get("restart_past_deadline") is True)
        context.check("preparation_does_not_renew_wait", facts.get("preparation_does_not_renew_wait") is True)

    def _verify_BRL_SC_006(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-006")
        context.check("single_terminal_outcome", facts.get("single_terminal_outcome") is True)
        context.check("transaction_order_authoritative", facts.get("transaction_order_authoritative") is True)
        context.check("release_or_debit_exclusive", facts.get("release_or_debit_exclusive") is True)
        context.check("no_duplicate_activation", facts.get("no_duplicate_activation") is True)
        context.check("start_expiry_cancel_serialized", facts.get("start_expiry_cancel_serialized") is True)
        context.check("valid_started_run_ignores_queue_expiry", facts.get("valid_started_run_ignores_queue_expiry") is True)
        context.check("no_post_start_release_from_queue_expiry", facts.get("no_post_start_release_from_queue_expiry") is True)
        context.check("cancel_before_start_commit", facts.get("cancel_before_start_commit") is True)
        context.check("cancel_after_start_commit", facts.get("cancel_after_start_commit") is True)
        context.check("concurrent_retry", facts.get("concurrent_retry") is True)
        context.check("owner_revocation_races_start", facts.get("owner_revocation_races_start") is True)
        context.check("queue_expiry_races_start_and_cancel", facts.get("queue_expiry_races_start_and_cancel") is True)
        context.check("expiry_delivery_after_valid_start", facts.get("expiry_delivery_after_valid_start") is True)
        context.check("duplicate_expiry_after_restart", facts.get("duplicate_expiry_after_restart") is True)

    def _verify_BRL_SC_007(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-007")
        context.check("utc_day_keys", facts.get("utc_day_keys") is True)
        context.check("current_day_start_rechecked", facts.get("current_day_start_rechecked") is True)
        context.check("quote_unchanged_at_rollover", facts.get("quote_unchanged_at_rollover") is True)
        context.check("rejected_start_releases_hold", facts.get("rejected_start_releases_hold") is True)
        context.check("refund_original_bucket", facts.get("refund_original_bucket") is True)
        context.check("next_reset_exposed", facts.get("next_reset_exposed") is True)
        context.check("new_day_budget_exhausted", facts.get("new_day_budget_exhausted") is True)
        context.check("limit_reduced_before_start", facts.get("limit_reduced_before_start") is True)
        context.check("refund_after_midnight", facts.get("refund_after_midnight") is True)
        context.check("duplicate_refund", facts.get("duplicate_refund") is True)

    def _verify_BRL_SC_008(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-008")
        context.check("manifest_order_preserved", facts.get("manifest_order_preserved") is True)
        context.check("one_current_task", facts.get("one_current_task") is True)
        context.check("task_state_isolated", facts.get("task_state_isolated") is True)
        context.check("future_or_foreign_action_rejected", facts.get("future_or_foreign_action_rejected") is True)
        context.check("future_task_action", facts.get("future_task_action") is True)
        context.check("completed_task_action", facts.get("completed_task_action") is True)
        context.check("foreign_run_task", facts.get("foreign_run_task") is True)
        context.check("shared_mutable_state_attempt", facts.get("shared_mutable_state_attempt") is True)

    def _verify_BRL_SC_009(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-009")
        context.check("ordinary_error_nonterminal", facts.get("ordinary_error_nonterminal") is True)
        context.check("retry_preserves_state", facts.get("retry_preserves_state") is True)
        context.check("violation_zero_irreversible", facts.get("violation_zero_irreversible") is True)
        context.check("remaining_tasks_continue", facts.get("remaining_tasks_continue") is True)
        context.check("preexecution_rejection_verified", facts.get("preexecution_rejection_verified") is True)
        context.check("unsafe_attempt_recorded_separately", facts.get("unsafe_attempt_recorded_separately") is True)
        context.check("rejected_attempt_allows_continuation", facts.get("rejected_attempt_allows_continuation") is True)
        context.check("explicit_attempt_prohibition_zero", facts.get("explicit_attempt_prohibition_zero") is True)
        context.check("reverted_operation", facts.get("reverted_operation") is True)
        context.check("reset_request", facts.get("reset_request") is True)
        context.check("later_balance_restoration_after_violation", facts.get("later_balance_restoration_after_violation") is True)
        context.check("attempt_to_reopen_violated_task", facts.get("attempt_to_reopen_violated_task") is True)
        context.check("forbidden_request_blocked_before_execution", facts.get("forbidden_request_blocked_before_execution") is True)
        context.check("published_attempt_itself_forbidden", facts.get("published_attempt_itself_forbidden") is True)
        context.check("unknown_effect_not_safe_rejection", facts.get("unknown_effect_not_safe_rejection") is True)

    def _verify_BRL_SC_010(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-010")
        context.check("same_state_after_reconnect", facts.get("same_state_after_reconnect") is True)
        context.check("deadline_not_extended", facts.get("deadline_not_extended") is True)
        context.check("restart_preserves_timer", facts.get("restart_preserves_timer") is True)
        context.check("expired_action_rejected", facts.get("expired_action_rejected") is True)
        context.check("foreign_read_rejected", facts.get("foreign_read_rejected") is True)
        context.check("transport_close", facts.get("transport_close") is True)
        context.check("agent_restart", facts.get("agent_restart") is True)
        context.check("coordinator_restart", facts.get("coordinator_restart") is True)
        context.check("reconnect_after_deadline", facts.get("reconnect_after_deadline") is True)
        context.check("foreign_agent_resume", facts.get("foreign_agent_resume") is True)

    def _verify_BRL_SC_011(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-011")
        context.check("deadline_action_cutoff", facts.get("deadline_action_cutoff") is True)
        context.check("verified_partial_outcome_retained", facts.get("verified_partial_outcome_retained") is True)
        context.check("pending_effect_reconciled", facts.get("pending_effect_reconciled") is True)
        context.check("next_task_if_time_remains", facts.get("next_task_if_time_remains") is True)
        context.check("overall_expiry_unranked", facts.get("overall_expiry_unranked") is True)
        context.check("missing_not_zero", facts.get("missing_not_zero") is True)
        context.check("partial_completion_at_deadline", facts.get("partial_completion_at_deadline") is True)
        context.check("inflight_action_at_cutoff", facts.get("inflight_action_at_cutoff") is True)
        context.check("missing_receipt", facts.get("missing_receipt") is True)
        context.check("overall_limit_with_tasks_remaining", facts.get("overall_limit_with_tasks_remaining") is True)

    def _verify_BRL_SC_012(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-012")
        context.check("reservation_released_once", facts.get("reservation_released_once") is True)
        context.check("no_start_debit", facts.get("no_start_debit") is True)
        context.check("no_task_execution", facts.get("no_task_execution") is True)
        context.check("cancel_stable_after_restart", facts.get("cancel_stable_after_restart") is True)
        context.check("revocation_blocks_before_cleanup", facts.get("revocation_blocks_before_cleanup") is True)
        context.check("revocation_cancels_all_queued_runs", facts.get("revocation_cancels_all_queued_runs") is True)
        context.check("mode_removal_scoped_to_affected_runs", facts.get("mode_removal_scoped_to_affected_runs") is True)
        context.check("unrelated_modes_preserved", facts.get("unrelated_modes_preserved") is True)
        context.check("permission_reenable_no_reopen", facts.get("permission_reenable_no_reopen") is True)
        context.check("waiting_expiry_reason_persisted", facts.get("waiting_expiry_reason_persisted") is True)
        context.check("original_cash_bonus_budget_holds_released_once", facts.get("original_cash_bonus_budget_holds_released_once") is True)
        context.check("released_bonus_terms_not_extended", facts.get("released_bonus_terms_not_extended") is True)
        context.check("no_automatic_resubmit_or_terminal_reopen", facts.get("no_automatic_resubmit_or_terminal_reopen") is True)
        context.check("expired_deadline_and_reason_private_readable", facts.get("expired_deadline_and_reason_private_readable") is True)
        context.check("late_callback_cannot_free_successor_slot", facts.get("late_callback_cannot_free_successor_slot") is True)
        context.check("cancel_while_preparing", facts.get("cancel_while_preparing") is True)
        context.check("duplicate_cancel", facts.get("duplicate_cancel") is True)
        context.check("late_start_delivery", facts.get("late_start_delivery") is True)
        context.check("owner_revokes_with_multiple_queued_runs", facts.get("owner_revokes_with_multiple_queued_runs") is True)
        context.check("revocation_delivery_after_restart", facts.get("revocation_delivery_after_restart") is True)
        context.check("remove_training_not_ranked", facts.get("remove_training_not_ranked") is True)
        context.check("remove_ranked_not_training", facts.get("remove_ranked_not_training") is True)
        context.check("mode_reenable_after_cancel", facts.get("mode_reenable_after_cancel") is True)
        context.check("cash_only_bonus_only_and_mixed_holds", facts.get("cash_only_bonus_only_and_mixed_holds") is True)
        context.check("queue_deadline_with_expired_bonus_lot", facts.get("queue_deadline_with_expired_bonus_lot") is True)
        context.check("expiry_while_preparing", facts.get("expiry_while_preparing") is True)
        context.check("same_key_retry_after_expiry", facts.get("same_key_retry_after_expiry") is True)
        context.check("late_prepare_callback_after_slot_handoff", facts.get("late_prepare_callback_after_slot_handoff") is True)
        context.check("later_timeout_policy_change", facts.get("later_timeout_policy_change") is True)

    def _verify_BRL_SC_013(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-013")
        context.check("post_start_charge_retained", facts.get("post_start_charge_retained") is True)
        context.check("no_voluntary_refund", facts.get("no_voluntary_refund") is True)
        context.check("late_actions_rejected", facts.get("late_actions_rejected") is True)
        context.check("partial_evidence_preserved", facts.get("partial_evidence_preserved") is True)
        context.check("cancelled_unranked", facts.get("cancelled_unranked") is True)
        context.check("revoked_agent_actions_rejected", facts.get("revoked_agent_actions_rejected") is True)
        context.check("reauthorization_does_not_reopen_cancelled_run", facts.get("reauthorization_does_not_reopen_cancelled_run") is True)
        context.check("mode_removal_scoped_to_affected_runs", facts.get("mode_removal_scoped_to_affected_runs") is True)
        context.check("unrelated_modes_preserved", facts.get("unrelated_modes_preserved") is True)
        context.check("permission_reenable_no_reopen", facts.get("permission_reenable_no_reopen") is True)
        context.check("cancel_after_first_task_activation", facts.get("cancel_after_first_task_activation") is True)
        context.check("duplicate_cancel", facts.get("duplicate_cancel") is True)
        context.check("late_action_after_cancel", facts.get("late_action_after_cancel") is True)
        context.check("owner_revokes_started_agent", facts.get("owner_revokes_started_agent") is True)
        context.check("delayed_observation_of_admitted_effect", facts.get("delayed_observation_of_admitted_effect") is True)
        context.check("reauthorization_after_revocation", facts.get("reauthorization_after_revocation") is True)
        context.check("remove_training_not_ranked", facts.get("remove_training_not_ranked") is True)
        context.check("remove_ranked_not_training", facts.get("remove_ranked_not_training") is True)
        context.check("mode_reenable_after_cancel", facts.get("mode_reenable_after_cancel") is True)

    def _verify_BRL_SC_014(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-014")
        context.check("original_effect_exists", facts.get("original_effect_exists") is True)
        context.check("same_transaction_observed", facts.get("same_transaction_observed") is True)
        context.check("no_action_resubmission", facts.get("no_action_resubmission") is True)
        context.check("single_chain_effect", facts.get("single_chain_effect") is True)
        context.check("recovery_interval_recorded", facts.get("recovery_interval_recorded") is True)
        context.check("original_evidence_preserved", facts.get("original_evidence_preserved") is True)
        context.check("response_lost_after_effect", facts.get("response_lost_after_effect") is True)
        context.check("recovery_worker_restart", facts.get("recovery_worker_restart") is True)
        context.check("duplicate_recovery_request", facts.get("duplicate_recovery_request") is True)
        context.check("different_transaction_offered", facts.get("different_transaction_offered") is True)

    def _verify_BRL_SC_015(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-015")
        context.check("platform_failure_attributed", facts.get("platform_failure_attributed") is True)
        context.check("unknown_retained", facts.get("unknown_retained") is True)
        context.check("recovery_exhausted", facts.get("recovery_exhausted") is True)
        context.check("single_refund", facts.get("single_refund") is True)
        context.check("unranked_terminal_stable", facts.get("unranked_terminal_stable") is True)
        context.check("missing_evidence", facts.get("missing_evidence") is True)
        context.check("contradictory_receipts", facts.get("contradictory_receipts") is True)
        context.check("duplicate_terminal_recovery", facts.get("duplicate_terminal_recovery") is True)
        context.check("late_receipt_after_refund", facts.get("late_receipt_after_refund") is True)

    def _verify_BRL_SC_016(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-016")
        context.check("training_feedback_after_task", facts.get("training_feedback_after_task") is True)
        context.check("ranked_scores_withheld_until_finish", facts.get("ranked_scores_withheld_until_finish") is True)
        context.check("ranked_final_scores_only", facts.get("ranked_final_scores_only") is True)
        context.check("tool_response_immediate", facts.get("tool_response_immediate") is True)
        context.check("foreign_feedback_rejected", facts.get("foreign_feedback_rejected") is True)
        context.check("ranked_result_scores_and_error_reasons", facts.get("ranked_result_scores_and_error_reasons") is True)
        context.check("no_participant_chronological_tool_journal", facts.get("no_participant_chronological_tool_journal") is True)
        context.check("closed_reason_allowlist", facts.get("closed_reason_allowlist") is True)
        context.check("closed_exact_parameters_absent", facts.get("closed_exact_parameters_absent") is True)
        context.check("necessary_scoped_tool_response_preserved", facts.get("necessary_scoped_tool_response_preserved") is True)
        context.check("ranked_early_score_request", facts.get("ranked_early_score_request") is True)
        context.check("training_feedback_before_task_terminal", facts.get("training_feedback_before_task_terminal") is True)
        context.check("reference_solution_field", facts.get("reference_solution_field") is True)
        context.check("foreign_result_request", facts.get("foreign_result_request") is True)
        context.check("request_internal_tool_trace_as_feedback", facts.get("request_internal_tool_trace_as_feedback") is True)
        context.check("closed_parameter_in_reason", facts.get("closed_parameter_in_reason") is True)
        context.check("ranked_feedback_before_terminal", facts.get("ranked_feedback_before_terminal") is True)
        context.check("closed_training_projection", facts.get("closed_training_projection") is True)

    def _verify_BRL_SC_017(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-017")
        context.check("complete_ranked_handoff_once", facts.get("complete_ranked_handoff_once") is True)
        context.check("training_not_eligible", facts.get("training_not_eligible") is True)
        context.check("unknown_not_eligible", facts.get("unknown_not_eligible") is True)
        context.check("incomplete_not_eligible", facts.get("incomplete_not_eligible") is True)
        context.check("achieving_version_snapshot_immutable", facts.get("achieving_version_snapshot_immutable") is True)
        context.check("eligible_terminal_and_shared_public_marker_same_commit", facts.get("eligible_terminal_and_shared_public_marker_same_commit") is True)
        context.check("ineligible_runs_no_publication_marker", facts.get("ineligible_runs_no_publication_marker") is True)
        context.check("training_completion", facts.get("training_completion") is True)
        context.check("missing_task", facts.get("missing_task") is True)
        context.check("unknown_outcome", facts.get("unknown_outcome") is True)
        context.check("duplicate_finalization", facts.get("duplicate_finalization") is True)
        context.check("profile_version_edited", facts.get("profile_version_edited") is True)
        context.check("terminal_marker_transaction_rollback", facts.get("terminal_marker_transaction_rollback") is True)
        context.check("caller_forges_publication_event", facts.get("caller_forges_publication_event") is True)

    def _verify_BRL_SC_018(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-018")
        context.check("monotonic_transition_sequence", facts.get("monotonic_transition_sequence") is True)
        context.check("source_and_payload_hashes", facts.get("source_and_payload_hashes") is True)
        context.check("raw_reference_hashes", facts.get("raw_reference_hashes") is True)
        context.check("original_bundle_immutable", facts.get("original_bundle_immutable") is True)
        context.check("divergence_or_missing_reported", facts.get("divergence_or_missing_reported") is True)
        context.check("boundary_label_preserved", facts.get("boundary_label_preserved") is True)
        context.check("event_payload_changed", facts.get("event_payload_changed") is True)
        context.check("missing_raw_artifact", facts.get("missing_raw_artifact") is True)
        context.check("restart_sequence_reuse", facts.get("restart_sequence_reuse") is True)
        context.check("local_evm_labelled_mainnet", facts.get("local_evm_labelled_mainnet") is True)

    def _verify_BRL_SC_019(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-019")
        context.check("one_slot_per_agent_across_modes_versions", facts.get("one_slot_per_agent_across_modes_versions") is True)
        context.check("queued_waiter_not_debited_or_timed", facts.get("queued_waiter_not_debited_or_timed") is True)
        context.check("slot_preserved_during_recovery", facts.get("slot_preserved_during_recovery") is True)
        context.check("predecessor_stopped_or_fenced_before_handoff", facts.get("predecessor_stopped_or_fenced_before_handoff") is True)
        context.check("stale_callback_cannot_release_successor", facts.get("stale_callback_cannot_release_successor") is True)
        context.check("different_agent_admitted_with_capacity", facts.get("different_agent_admitted_with_capacity") is True)
        context.check("owner_rotation_with_multiple_eligible_owners", facts.get("owner_rotation_with_multiple_eligible_owners") is True)
        context.check("oldest_eligible_request_inside_owner", facts.get("oldest_eligible_request_inside_owner") is True)
        context.check("busy_agent_head_does_not_block_other_agent", facts.get("busy_agent_head_does_not_block_other_agent") is True)
        context.check("durable_dispatch_turn_and_claim", facts.get("durable_dispatch_turn_and_claim") is True)
        context.check("duplicate_dispatch_not_extra_owner_turn", facts.get("duplicate_dispatch_not_extra_owner_turn") is True)
        context.check("no_running_run_preemption", facts.get("no_running_run_preemption") is True)
        context.check("sole_owner_uses_spare_capacity_within_bounds", facts.get("sole_owner_uses_spare_capacity_within_bounds") is True)
        context.check("original_queue_order_deadline_retained", facts.get("original_queue_order_deadline_retained") is True)
        context.check("same_agent_ranked_training_race", facts.get("same_agent_ranked_training_race") is True)
        context.check("same_agent_different_declared_versions", facts.get("same_agent_different_declared_versions") is True)
        context.check("duplicate_worker_delivery", facts.get("duplicate_worker_delivery") is True)
        context.check("restart_with_live_executor", facts.get("restart_with_live_executor") is True)
        context.check("cancel_with_pending_effect", facts.get("cancel_with_pending_effect") is True)
        context.check("delayed_release_after_successor_claim", facts.get("delayed_release_after_successor_claim") is True)
        context.check("recovery_retains_slot", facts.get("recovery_retains_slot") is True)
        context.check("one_owner_many_agents_other_owner_waiting", facts.get("one_owner_many_agents_other_owner_waiting") is True)
        context.check("same_owner_busy_oldest_and_ready_younger_agent", facts.get("same_owner_busy_oldest_and_ready_younger_agent") is True)
        context.check("duplicate_scheduler_workers", facts.get("duplicate_scheduler_workers") is True)
        context.check("restart_after_dispatch_claim", facts.get("restart_after_dispatch_claim") is True)
        context.check("owner_temporarily_has_no_eligible_request", facts.get("owner_temporarily_has_no_eligible_request") is True)
        context.check("sole_eligible_owner_multiple_free_agent_slots", facts.get("sole_eligible_owner_multiple_free_agent_slots") is True)
        context.check("multiple_sessions_same_owner_not_new_turn", facts.get("multiple_sessions_same_owner_not_new_turn") is True)

    def _verify_BRL_SC_020(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-020")
        context.check("explicit_finish_authenticated", facts.get("explicit_finish_authenticated") is True)
        context.check("one_persisted_finish_or_deadline_cutoff", facts.get("one_persisted_finish_or_deadline_cutoff") is True)
        context.check("postcutoff_and_foreign_actions_rejected", facts.get("postcutoff_and_foreign_actions_rejected") is True)
        context.check("admitted_effect_observed_without_resubmission", facts.get("admitted_effect_observed_without_resubmission") is True)
        context.check("completion_state_and_violation_history_used", facts.get("completion_state_and_violation_history_used") is True)
        context.check("agent_score_not_authoritative", facts.get("agent_score_not_authoritative") is True)
        context.check("one_evaluation_posting_and_next_task_activation", facts.get("one_evaluation_posting_and_next_task_activation") is True)
        context.check("finish_action_deadline_race", facts.get("finish_action_deadline_race") is True)
        context.check("duplicate_finish_after_restart", facts.get("duplicate_finish_after_restart") is True)
        context.check("local_evm_receipt_pending_at_finish", facts.get("local_evm_receipt_pending_at_finish") is True)
        context.check("foreign_agent_finish", facts.get("foreign_agent_finish") is True)
        context.check("forged_success_or_score", facts.get("forged_success_or_score") is True)
        context.check("mandatory_violation_retained", facts.get("mandatory_violation_retained") is True)

    def _verify_BRL_SC_021(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-021")
        context.check("trusted_finding_run_actor_binding", facts.get("trusted_finding_run_actor_binding") is True)
        context.check("disqualified_terminal_once", facts.get("disqualified_terminal_once") is True)
        context.check("postfinding_action_cutoff", facts.get("postfinding_action_cutoff") is True)
        context.check("ranked_handoff_absent", facts.get("ranked_handoff_absent") is True)
        context.check("original_charge_retained_no_extra_debit", facts.get("original_charge_retained_no_extra_debit") is True)
        context.check("evidence_and_other_owner_funds_preserved", facts.get("evidence_and_other_owner_funds_preserved") is True)
        context.check("duplicate_finding_after_restart", facts.get("duplicate_finding_after_restart") is True)
        context.check("late_action_after_cutoff", facts.get("late_action_after_cutoff") is True)
        context.check("foreign_run_or_actor_binding", facts.get("foreign_run_or_actor_binding") is True)
        context.check("attempt_to_reopen_disqualified_run", facts.get("attempt_to_reopen_disqualified_run") is True)
        context.check("finding_after_existing_terminal_decision", facts.get("finding_after_existing_terminal_decision") is True)

    def _verify_BRL_SC_022(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-022")
        context.check("untrusted_or_incomplete_finding_rejected", facts.get("untrusted_or_incomplete_finding_rejected") is True)
        context.check("claim_not_successful_interference", facts.get("claim_not_successful_interference") is True)
        context.check("blocked_attempt_rule_preserved", facts.get("blocked_attempt_rule_preserved") is True)
        context.check("unknown_result_explicit", facts.get("unknown_result_explicit") is True)
        context.check("no_punitive_or_duplicate_charge", facts.get("no_punitive_or_duplicate_charge") is True)
        context.check("no_action_reexecution", facts.get("no_action_reexecution") is True)
        context.check("agent_claims_hack", facts.get("agent_claims_hack") is True)
        context.check("forged_observer_identity", facts.get("forged_observer_identity") is True)
        context.check("missing_evidence_or_bad_hash", facts.get("missing_evidence_or_bad_hash") is True)
        context.check("contradictory_observations", facts.get("contradictory_observations") is True)
        context.check("blocked_request_without_effect", facts.get("blocked_request_without_effect") is True)

    def _verify_BRL_SC_023(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-023")
        context.check("owner_bound_immutable_intent", facts.get("owner_bound_immutable_intent") is True)
        context.check("pending_no_run_hold_slot_or_timer", facts.get("pending_no_run_hold_slot_or_timer") is True)
        context.check("one_server_derived_admission_identity", facts.get("one_server_derived_admission_identity") is True)
        context.check("atomic_intent_run_reservation_link", facts.get("atomic_intent_run_reservation_link") is True)
        context.check("exact_reviewed_quote_and_cash_ceiling", facts.get("exact_reviewed_quote_and_cash_ceiling") is True)
        context.check("retry_after_expiry_price_or_version_change_same_run", facts.get("retry_after_expiry_price_or_version_change_same_run") is True)
        context.check("no_card_publication_or_model_execution", facts.get("no_card_publication_or_model_execution") is True)
        context.check("duplicate_create_or_accept", facts.get("duplicate_create_or_accept") is True)
        context.check("new_caller_key_same_intent", facts.get("new_caller_key_same_intent") is True)
        context.check("cross_transport_retry", facts.get("cross_transport_retry") is True)
        context.check("lost_response_restart", facts.get("lost_response_restart") is True)
        context.check("admitted_retry_after_expiry", facts.get("admitted_retry_after_expiry") is True)
        context.check("admitted_retry_after_version_or_tariff_change", facts.get("admitted_retry_after_version_or_tariff_change") is True)

    def _verify_BRL_SC_024(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-024")
        context.check("matching_current_agent_authority_required", facts.get("matching_current_agent_authority_required") is True)
        context.check("changed_quote_version_selection_or_cash_rejected", facts.get("changed_quote_version_selection_or_cash_rejected") is True)
        context.check("no_run_or_holds_on_rejection", facts.get("no_run_or_holds_on_rejection") is True)
        context.check("cancel_expiry_accept_serialized", facts.get("cancel_expiry_accept_serialized") is True)
        context.check("postadmission_cancel_uses_run_rules", facts.get("postadmission_cancel_uses_run_rules") is True)
        context.check("bounded_intent_admission", facts.get("bounded_intent_admission") is True)
        context.check("foreign_data_absent", facts.get("foreign_data_absent") is True)
        context.check("owner_session_as_agent", facts.get("owner_session_as_agent") is True)
        context.check("foreign_owner_or_card", facts.get("foreign_owner_or_card") is True)
        context.check("changed_payload", facts.get("changed_payload") is True)
        context.check("stale_tariff_or_benchmark", facts.get("stale_tariff_or_benchmark") is True)
        context.check("increased_cash_need", facts.get("increased_cash_need") is True)
        context.check("cash_permission_revoked", facts.get("cash_permission_revoked") is True)
        context.check("at_deadline_accept", facts.get("at_deadline_accept") is True)
        context.check("cancel_accept_race", facts.get("cancel_accept_race") is True)
        context.check("pending_intent_capacity_exhaustion", facts.get("pending_intent_capacity_exhaustion") is True)
        context.check("same_key_conflicting_creation", facts.get("same_key_conflicting_creation") is True)

    def _verify_BRL_SC_025(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        facts = self._facts_for_verification(context, "BRL-SC-025")
        context.check("actual_backend_postgres_current_quote_binding", facts.get("actual_backend_postgres_current_quote_binding") is True)
        context.check("actual_browser_current_three_task_selection_and_quote", facts.get("actual_browser_current_three_task_selection_and_quote") is True)
        context.check("real_owner_ui_waiting_before_admission", facts.get("real_owner_ui_waiting_before_admission") is True)
        context.check("linked_run_only_after_commit", facts.get("linked_run_only_after_commit") is True)
        context.check("reload_same_handoff_identity", facts.get("reload_same_handoff_identity") is True)
        context.check("native_selected_client_action_evidence", facts.get("native_selected_client_action_evidence") is True)
        context.check("fallback_setup_approvals_counted_separately", facts.get("fallback_setup_approvals_counted_separately") is True)
        context.check("no_secret_in_link_or_prompt", facts.get("no_secret_in_link_or_prompt") is True)
        context.check("no_hosted_model_invocation", facts.get("no_hosted_model_invocation") is True)
        context.check("client_never_responds", facts.get("client_never_responds") is True)
        context.check("copy_request_fallback", facts.get("copy_request_fallback") is True)
        context.check("extra_native_approval", facts.get("extra_native_approval") is True)
        context.check("reload_back_double_click", facts.get("reload_back_double_click") is True)
        context.check("stale_review_required", facts.get("stale_review_required") is True)
        context.check("unsupported_client_without_short_path_claim", facts.get("unsupported_client_without_short_path_claim") is True)

def register(registry: ScenarioRegistry) -> None:
    proposal, contract, _ = _load_contract_sources()
    for scenario_id in SCENARIO_IDS:
        registry.register(
            scenario_id,
            ExplicitBenchmarkRunLifecycleEvidenceCase(
                scenario_id,
                proposal["protected_scenarios"][scenario_id],
                contract["protected_scenarios"][scenario_id],
            ),
            adapter_profile=proposal["protected_scenarios"][scenario_id]["adapter"],
        )
