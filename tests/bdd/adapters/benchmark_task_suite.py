"""Fail-closed adapter for the approved 34-scenario BTS delta.

SC-001/002 derive release facts from retained manifests, verifier inputs, candidate
mutations, and read-only database snapshots. SC-009 derives actual ranked state but
stays blocked until its persisted-unknown negative is covered. Other scenarios need
their own hash-pinned runtime bundles; missing evidence stays blocked.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from fractions import Fraction
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from tests.bdd.adapters import ScenarioContext, ScenarioRegistry
from tests.bdd.adapters.benchmark_run_lifecycle import _verify_source_inventory

CHANGE_NAME = "benchmark-task-suite"
SCENARIO_IDS = tuple(f"BTS-SC-{number:03d}" for number in range(1, 35))
ADAPTER_PROFILES = frozenset({"benchmark_task_suite_http_evm_adapter"})
# SC-009 remains blocked until the separate persisted-unknown outcome variant is
# exercised. The release gates can pass only after every contract observation
# and negative is independently derived from the raw probe capture below.
PASSABLE_SCENARIOS: frozenset[str] = frozenset({"BTS-SC-001", "BTS-SC-002"})
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
TASK_IDS = ("S1", "S2", "S3", "S4", "M1", "M2", "M3", "M4", "H1", "H2", "H3", "U1")
TRAINING_IDS = ("S1", "M1", "H1")
TASK_WEIGHTS = {"S1": 1, "S2": 1, "S3": 1, "S4": 1, "M1": 2, "M2": 2,
                "M3": 2, "M4": 2, "H1": 3, "H2": 3, "H3": 3, "U1": 5}
REFERENCE_ACTION_PLANS = {
    "S1": ("transfer",),
    "S2": ("inspect_offer",),
    "S3": ("inspect_catalog",),
    "S4": ("revoke",),
    "M1": ("inspect_offer", "pay", "retrieve"),
    "M2": ("inspect_catalog", "pay", "retrieve"),
    "M3": ("approve", "swap", "unwrap"),
    "M4": ("wrap", "approve", "swap"),
    "H1": ("inspect_catalog", "pay", "retrieve", "pay", "retrieve", "pay", "retrieve"),
    "H2": ("transfer", "transfer", "transfer", "transfer", "transfer", "transfer"),
    "H3": ("inspect_offer", "pay", "retrieve", "wrap", "approve", "swap"),
    "U1": ("inspect_catalog", "pay", "retrieve", "pay", "retrieve", "transfer", "transfer", "approve", "swap", "unwrap"),
}
TASK_LEVELS = {"S1": "simple", "S2": "simple", "S3": "simple", "S4": "simple",
               "M1": "medium", "M2": "medium", "M3": "medium", "M4": "medium",
               "H1": "hard", "H2": "hard", "H3": "hard", "U1": "ultra"}
CASE_OBJECTIVE_KEYS = {
    "S1": {"tokenAssetId", "sender", "recipient", "exactPrincipalUnits", "nativeReserveWei", "unrelatedEffectBaselineSha256"},
    "S2": {"resourceId", "offerId", "completePaymentRequirements", "requiredAnswerFields"},
    "S3": {"catalog", "required"},
    "S4": {"tokenAssetId", "owner", "spender", "initialAllowanceUnits", "unrelatedAllowanceBaselineSha256"},
    "M1": {"component", "paymentRequirements", "expenseBudgetUsdcUnits", "duplicatePurchaseIdentity"},
    "M2": {"catalog", "required", "expenseBudgetUsdcUnits", "tiePolicy", "duplicatePurchaseIdentity"},
    "M3": {"inputAssetId", "exactInputUnits", "outputAssetId", "minimumNativeOutputWei", "permittedRoutes", "maxSlippageBps", "nativeReserveWei", "expenseBudgetUsdcUnits"},
    "M4": {"inputAssetId", "exactInputUnits", "outputAssetId", "minimumOutputUnits", "permittedRoutes", "initialAllowanceScope", "nativeReserveWei", "expenseBudgetUsdcUnits"},
    "H1": {"requiredComponents", "permittedSources", "expenseBudgetUsdcUnits", "duplicatePurchaseIdentity"},
    "H2": {"obligations", "initialAssetIds", "permittedConversions", "nativeReserveWei", "expenseBudgetUsdcUnits"},
    "H3": {"referenceComponent", "routeObjective", "inputAssetId", "exactInputUnits", "permittedRoutes", "minimumOutputUnits", "nativeReserveWei", "combinedExpenseBudgetUsdcUnits"},
    "U1": {"requiredComponents", "permittedSources", "permittedRoutes", "allocationAssets", "payoutObligations", "temporarySpenderScope", "nativeReserveWei", "expenseBudgetUsdcUnits", "duplicatePurchaseIdentity"},
}
RELEASE_VARIANT_REQUIREMENTS = {
    "placeholder": ("cases.ranked.M1.caseId", (("placeholder_or_latest_value", "ranked/M1/"),)),
    "wrong_block_identity": ("executionIdentity.sourceBlockNumber", (("missing_feasibility_evidence", "feasibilityEvidence"),)),
    "wrong_contract_code_identity": ("executionIdentity.contracts[pool].codeHash", (("missing_feasibility_evidence", "feasibilityEvidence"),)),
    "initially_satisfied_paid_case": ("cases.ranked.M1.initialState.deliveredComponentIds", (("unsolvable_or_initially_solved_case", "ranked/M1/"),)),
    "initially_fulfilled_payout_obligation": ("cases.ranked.H2.initialState.fulfilledObligationIds", (("invalid_task_reference", "ranked/H2/"),)),
    "missing_reference_evidence": ("cases.training.S1.referencePath.evidence.path", (("reference_path_evidence_unavailable", "training/S1/"),)),
    "no_qualifying_catalog_offer": ("cases.ranked.S3.objective.required.requiredDataType", (("invalid_catalog_predicates", "ranked/S3/"),)),
    "empty_u1_component_set": ("cases.ranked.11.objective.requiredComponents", (("manifest_schema_invalid", "cases.ranked.11.objective.requiredComponents"),)),
    "duplicate_u1_component": ("cases.ranked.U1.objective.requiredComponents", (("invalid_u1_fixed_sets", "ranked/U1/"),)),
    "incomplete_u1_component_validator": ("cases.ranked.U1.objective.requiredComponents[0].validator.requiredFields", (("missing_component_validator_field", "ranked/U1/"), ("invalid_u1_fixed_sets", "ranked/U1/"))),
    "empty_u1_allocation_asset_set": ("cases.ranked.11.objective.allocationAssets", (("manifest_schema_invalid", "cases.ranked.11.objective.allocationAssets"),)),
    "duplicate_u1_allocation_asset": ("cases.ranked.U1.objective.allocationAssets", (("invalid_u1_fixed_sets", "ranked/U1/"),)),
    "fewer_than_two_u1_payout_obligations": ("cases.ranked.11.objective.payoutObligations", (("manifest_schema_invalid", "cases.ranked.11.objective.payoutObligations"),)),
    "duplicate_u1_payout_obligation": ("cases.ranked.U1.objective.payoutObligations", (("invalid_u1_fixed_sets", "ranked/U1/"),)),
    "empty_u1_temporary_spender_set": ("cases.ranked.11.objective.temporarySpenderScope", (("manifest_schema_invalid", "cases.ranked.11.objective.temporarySpenderScope"),)),
    "duplicate_u1_temporary_spender": ("cases.ranked.U1.objective.temporarySpenderScope", (("invalid_u1_fixed_sets", "ranked/U1/"),)),
    "initially_satisfied_u1_allocation": ("cases.ranked.U1.initialState.balances", (("invalid_u1_fixed_sets", "ranked/U1/"),)),
}
SC001_NEGATIVE_MAP = {
    "placeholder": ("placeholder",),
    "wrong_block_or_code": ("wrong_block_identity", "wrong_contract_code_identity"),
    "unsolvable_or_initially_solved": ("initially_satisfied_paid_case", "initially_fulfilled_payout_obligation"),
    "missing_reference_evidence": ("missing_reference_evidence",),
}
SC002_NEGATIVE_MAP = {
    **SC001_NEGATIVE_MAP,
    "empty_or_duplicate_u1_components": ("empty_u1_component_set", "duplicate_u1_component"),
    "missing_or_incomplete_u1_component_validator": ("incomplete_u1_component_validator",),
    "empty_or_duplicate_u1_allocation_assets": ("empty_u1_allocation_asset_set", "duplicate_u1_allocation_asset"),
    "fewer_than_two_or_duplicate_u1_payout_obligations": ("fewer_than_two_u1_payout_obligations", "duplicate_u1_payout_obligation"),
    "empty_or_duplicate_u1_temporary_spender_set": ("empty_u1_temporary_spender_set", "duplicate_u1_temporary_spender"),
    "initially_satisfied_u1_final_allocation": ("initially_satisfied_u1_allocation",),
}


def _assert_secret_free(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key), flags=re.IGNORECASE)
            if SECRET_KEY_RE.fullmatch(normalized):
                allowed_redacted_authorization = bool(
                    str(key).casefold() == "authorization"
                    and path.endswith(".request.headers")
                    and isinstance(child, str)
                    and child.casefold() in {"<redacted>", "[redacted]"}
                )
                if not allowed_redacted_authorization:
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
        raise AssertionError("BTS approved and runtime contract inventories are incomplete or inconsistent")
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
            raise AssertionError(f"{scenario_id} uses an unregistered BTS adapter profile")
    if {proposal_rows[scenario_id]["adapter"] for scenario_id in SCENARIO_IDS} != ADAPTER_PROFILES:
        raise AssertionError("BTS adapter profile inventory drifted")
    return proposal, contract, contract_bytes


def _inside(root: Path, path: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved_root not in resolved.parents:
        raise AssertionError("BTS evidence path escapes its declared root")
    return resolved


def _load_run(scenario_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]] | None:
    if scenario_id not in SCENARIO_IDS:
        raise ValueError(f"Unsupported BTS scenario identity: {scenario_id}")
    scenario_root = EVIDENCE_ROOT / scenario_id
    index_path = scenario_root / "manifest.json"
    if not index_path.is_file():
        return None
    index = _read_object(index_path)
    if (
        index.get("schemaVersion") != "benchmark-task-suite-evidence-index/v1"
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
        manifest.get("schemaVersion") != "benchmark-task-suite-acceptance/v1"
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
        raise AssertionError(f"{scenario_id} evidence is not bound to the current BTS runtime contract")
    if scenario_id in {"BTS-SC-001", "BTS-SC-002", "BTS-SC-009"} and manifest.get("status") == "passed":
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


def _canonical_json(value: Any) -> bytes:
    """Match task-release canonical JSON for the integer/string-only BTS schema."""
    if isinstance(value, float):
        raise AssertionError("BTS hash input contains a floating-point value")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _without_key(value: dict[str, Any], key: str) -> dict[str, Any]:
    return {name: child for name, child in value.items() if name != key}


def _repo_artifact_path(root: Path, relative: Any) -> Path:
    if (
        not isinstance(relative, str)
        or not ARTIFACT_PATH_RE.fullmatch(relative)
        or "\\" in relative
        or relative.startswith("/")
        or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
    ):
        raise AssertionError("BTS raw artifact path is unsafe")
    return _inside(root, root.joinpath(*PurePosixPath(relative).parts))


def _read_pinned_repo_json(root: Path, relative: Any, digest: Any, *, max_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise AssertionError("BTS raw artifact has an invalid SHA-256 pin")
    path = _repo_artifact_path(root, relative)
    content = path.read_bytes()
    if not content or len(content) > max_bytes:
        raise AssertionError("BTS raw artifact size is outside the accepted bound")
    if hashlib.sha256(content).hexdigest() != digest:
        raise AssertionError("BTS raw artifact hash mismatch")
    value = json.loads(content.decode("utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("BTS raw artifact must be a JSON object")
    _assert_secret_free(value, str(relative))
    return value


def _valid_units(value: Any, *, positive: bool = False) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,77})", value):
        return False
    return not positive or int(value) > 0


def _state_projection(state: Any) -> dict[str, Any] | None:
    if not isinstance(state, dict):
        return None
    balances = state.get("balances")
    allowances = state.get("allowances")
    delivered = state.get("deliveredComponentIds")
    fulfilled = state.get("fulfilledObligationIds")
    if not isinstance(balances, list) or not isinstance(allowances, list) or not isinstance(delivered, list) or not isinstance(fulfilled, list):
        return None
    try:
        sorted_balances = sorted(balances, key=lambda row: f"{row['account'].lower()}|{row['assetId']}")
        sorted_allowances = sorted(allowances, key=lambda row: f"{row['owner'].lower()}|{row['tokenAssetId']}|{row['spender'].lower()}")
    except (KeyError, AttributeError, TypeError):
        return None
    if any(not isinstance(row, dict) or not _valid_units(row.get("amountUnits")) for row in sorted_balances + sorted_allowances):
        return None
    if any(not isinstance(value, str) for value in delivered + fulfilled):
        return None
    return {
        "balances": sorted_balances,
        "allowances": sorted_allowances,
        "deliveredComponentIds": sorted(delivered),
        "fulfilledObligationIds": sorted(fulfilled),
    }


def _valid_component(component: Any) -> bool:
    if not isinstance(component, dict) or not isinstance(component.get("componentId"), str) or not isinstance(component.get("resourceId"), str):
        return False
    if not isinstance(component.get("sourceIds"), list) or not component["sourceIds"] or len(set(component["sourceIds"])) != len(component["sourceIds"]):
        return False
    validator = component.get("validator")
    if not isinstance(validator, dict) or validator.get("additionalProperties") is not False:
        return False
    if not all(isinstance(validator.get(key), str) and validator[key] for key in ("validatorVersion", "payloadSchemaVersion")):
        return False
    fields = validator.get("requiredFields")
    predicates = validator.get("predicates")
    provenance = validator.get("permittedProvenance")
    if not isinstance(fields, list) or not fields or not isinstance(predicates, list) or not predicates or not isinstance(provenance, list) or not provenance:
        return False
    names = [field.get("name") for field in fields if isinstance(field, dict)]
    return len(names) == len(fields) and len(set(names)) == len(names) and all(isinstance(row, str) and row for row in provenance)


def _valid_case_shape(task_case: Any, expected_mode: str, task_id: str, execution_hash: str) -> bool:
    if not isinstance(task_case, dict) or task_case.get("taskId") != task_id or task_case.get("mode") != expected_mode:
        return False
    if task_case.get("taskWeight") != TASK_WEIGHTS[task_id] or task_case.get("executionIdentityHash") != execution_hash:
        return False
    if not isinstance(task_case.get("caseId"), str) or not task_case["caseId"] or task_case.get("rubricVersion") != "bts-rubric/v1":
        return False
    if not isinstance(task_case.get("rubricHash"), str) or not SHA256_RE.fullmatch(task_case["rubricHash"]):
        return False
    objective = task_case.get("objective")
    if not isinstance(objective, dict) or set(objective) != CASE_OBJECTIVE_KEYS[task_id]:
        return False
    projection = _state_projection(task_case.get("initialState"))
    if projection is None or task_case["initialState"].get("stateSha256") != _sha256_json(projection):
        return False
    if not isinstance(task_case.get("mandatoryRules"), list) or not task_case["mandatoryRules"]:
        return False
    reference = task_case.get("referencePath")
    if not isinstance(reference, dict) or not isinstance(reference.get("actionCount"), int) or isinstance(reference.get("actionCount"), bool) or reference["actionCount"] <= 0:
        return False
    if not isinstance(reference.get("initialStateSha256"), str) or not SHA256_RE.fullmatch(reference["initialStateSha256"]):
        return False
    if not isinstance(reference.get("finalStateSha256"), str) or not SHA256_RE.fullmatch(reference["finalStateSha256"]):
        return False
    if not isinstance(reference.get("toolSurfaceSha256"), str) or not SHA256_RE.fullmatch(reference["toolSurfaceSha256"]):
        return False
    refs = (task_case.get("initialStateEvidence"), reference.get("evidence"))
    if any(not isinstance(ref, dict) or ref.get("boundary") != "actual_tool_http_x402_local_evm_application_store"
           or not isinstance(ref.get("path"), str) or not isinstance(ref.get("sha256"), str) or not SHA256_RE.fullmatch(ref["sha256"])
           for ref in refs):
        return False
    if task_id in {"H1", "U1"}:
        components = objective.get("requiredComponents")
        if not isinstance(components, list) or not components or not all(_valid_component(row) for row in components):
            return False
        if len({row["componentId"] for row in components}) != len(components):
            return False
    elif task_id == "M1":
        if not _valid_component(objective.get("component")):
            return False
    elif task_id == "H3":
        if not _valid_component(objective.get("referenceComponent")):
            return False
    if task_id in {"S3", "M2"} and (not isinstance(objective.get("catalog"), list) or len(objective["catalog"]) < 2):
        return False
    if task_id in {"H2", "U1"}:
        obligations = objective.get("obligations") if task_id == "H2" else objective.get("payoutObligations")
        if not isinstance(obligations, list) or len(obligations) < 2:
            return False
        obligation_ids = [row.get("obligationId") for row in obligations if isinstance(row, dict)]
        if len(obligation_ids) != len(obligations) or len(set(obligation_ids)) != len(obligation_ids):
            return False
    return True


def _verify_task_manifest(manifest: Any) -> tuple[bool, list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != "bts-task-release/v1":
        return False, [], []
    if manifest.get("manifestHash") != _sha256_json(_without_key(manifest, "manifestHash")):
        return False, [], []
    identity = manifest.get("executionIdentity")
    if not isinstance(identity, dict):
        return False, [], []
    execution_hash = _sha256_json(identity)
    if manifest.get("executionIdentityHash") != execution_hash:
        return False, [], []
    inventory = manifest.get("inventory")
    cases = manifest.get("cases")
    if not isinstance(inventory, dict) or inventory.get("orderedTaskIds") != list(TASK_IDS) or inventory.get("rankedWeightSum") != 26:
        return False, [], []
    if inventory.get("openTrainingTaskIds") != list(TRAINING_IDS) or inventory.get("openTrainingWeightSum") != 6:
        return False, [], []
    if inventory.get("closedRankedOnlyTaskIds") != [task_id for task_id in TASK_IDS if task_id not in TRAINING_IDS]:
        return False, [], []
    if not isinstance(cases, dict) or not isinstance(cases.get("training"), list) or not isinstance(cases.get("ranked"), list):
        return False, [], []
    training, ranked = cases["training"], cases["ranked"]
    if len(training) != 3 or len(ranked) != 12:
        return False, [], []
    if [row.get("taskId") for row in training if isinstance(row, dict)] != list(TRAINING_IDS):
        return False, [], []
    if [row.get("taskId") for row in ranked if isinstance(row, dict)] != list(TASK_IDS):
        return False, [], []
    valid = True
    all_cases = []
    for mode, collection, expected_ids in (("training", training, TRAINING_IDS), ("ranked", ranked, TASK_IDS)):
        for task_case, task_id in zip(collection, expected_ids, strict=True):
            if not _valid_case_shape(task_case, mode, task_id, execution_hash):
                valid = False
            if not isinstance(task_case, dict) or task_case.get("caseHash") != _sha256_json(_without_key(task_case, "caseHash")):
                valid = False
            all_cases.append(task_case)
    expected_benchmark = _sha256_json({
        "benchmarkVersion": manifest.get("benchmarkVersion"),
        "executionIdentityHash": execution_hash,
        "policyHash": manifest.get("policyHash"),
        "trainingCaseHashes": [{"taskId": row.get("taskId"), "caseHash": row.get("caseHash")} for row in training],
        "rankedCaseHashes": [{"taskId": row.get("taskId"), "caseHash": row.get("caseHash")} for row in ranked],
    })
    if manifest.get("benchmarkHash") != expected_benchmark:
        valid = False
    if len({(row.get("mode"), row.get("caseId")) for row in all_cases if isinstance(row, dict)}) != len(all_cases):
        valid = False
    return valid, training, ranked


def _verify_reference_evidence(root: Path, task_case: dict[str, Any], execution_hash: str) -> tuple[bool, int]:
    task_id, mode = task_case["taskId"], task_case["mode"]
    reference = task_case["referencePath"]
    envelope_ref = reference["evidence"]
    baseline_ref = task_case["initialStateEvidence"]
    envelope = _read_pinned_repo_json(root, envelope_ref.get("path"), envelope_ref.get("sha256"))
    baseline = _read_pinned_repo_json(root, baseline_ref.get("path"), baseline_ref.get("sha256"))
    if not (
        envelope.get("schemaVersion") == "bts-task-case-evidence-composition/v2"
        and envelope.get("purpose") == "reference_execution_trace"
        and envelope.get("taskId") == task_id and envelope.get("mode") == mode
        and envelope.get("caseId") == task_case.get("caseId")
        and envelope.get("executionIdentityHash") == execution_hash
        and baseline.get("schemaVersion") == envelope.get("schemaVersion")
        and baseline.get("purpose") == "initial_state_projection"
        and baseline.get("taskId") == task_id and baseline.get("mode") == mode
        and baseline.get("caseId") == task_case.get("caseId")
        and baseline.get("executionIdentityHash") == execution_hash
        and baseline.get("taskStateSha256") == task_case.get("initialState", {}).get("stateSha256")
        and baseline.get("probe") == envelope.get("probe")
        and baseline.get("rawReferences") == envelope.get("rawReferences")
    ):
        return False, 0
    probe_ref = envelope.get("probe")
    if not isinstance(probe_ref, dict):
        return False, 0
    probe = _read_pinned_repo_json(root, probe_ref.get("path"), probe_ref.get("sha256"))
    if not (
        probe.get("schemaVersion") == "bts-difficulty-v2-reference-probe/v1"
        and probe.get("status") == "captured"
        and probe.get("taskId") == task_id and probe.get("mode") == mode
        and probe.get("participantToolProtocol") == "separate_payment_delivery_v2"
        and probe.get("noTaskGrade") is True
        and probe.get("noReleaseActivation") is True
        and probe.get("noAcceptanceClaim") is True
    ):
        return False, 0
    capture_root = PurePosixPath(probe_ref["path"]).parent.as_posix()
    raw_references = envelope.get("rawReferences")
    artifacts = probe.get("artifacts")
    if not isinstance(raw_references, list) or not isinstance(artifacts, list) or not artifacts or len(artifacts) > 512:
        return False, 0
    raw_by_path: dict[str, dict[str, Any]] = {}
    for row in raw_references:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str) or row["path"] in raw_by_path:
            return False, 0
        raw_by_path[row["path"]] = row
    artifact_documents: dict[str, dict[str, Any]] = {}
    artifact_hashes: dict[str, str] = {}
    total_bytes = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            return False, 0
        relative = artifact.get("path")
        full_path = f"{capture_root}/{relative}" if isinstance(relative, str) else None
        listed = raw_by_path.get(full_path)
        if not listed or listed.get("sha256") != artifact.get("sha256") or listed.get("boundary") != artifact.get("boundary"):
            return False, 0
        document = _read_pinned_repo_json(root, full_path, artifact.get("sha256"))
        total_bytes += _repo_artifact_path(root, full_path).stat().st_size
        if total_bytes > 128 * 1024 * 1024:
            return False, 0
        artifact_documents[relative] = document
        artifact_hashes[relative] = artifact["sha256"]
    if len(raw_by_path) != len(artifact_documents):
        return False, 0
    manifest_ref = probe.get("manifest")
    if (not isinstance(manifest_ref, dict) or manifest_ref.get("path") not in artifact_documents
            or manifest_ref.get("sha256") != artifact_hashes.get(manifest_ref.get("path"))):
        return False, 0
    actions = probe.get("captureReferences", {}).get("participantActions") if isinstance(probe.get("captureReferences"), dict) else None
    expected_plan = REFERENCE_ACTION_PLANS.get(task_id)
    if (not isinstance(actions, list) or expected_plan is None
            or len(actions) != task_case["referencePath"]["actionCount"]
            or tuple(action.get("kind") for action in actions if isinstance(action, dict)) != expected_plan):
        return False, 0
    if probe.get("participantActionCount") != len(actions):
        return False, 0
    seen_operations: set[str] = set()
    for action in actions:
        if not isinstance(action, dict) or action.get("kind") not in expected_plan:
            return False, 0
        operation_id = action.get("operationId")
        if not isinstance(operation_id, str) or not UUID_RE.fullmatch(operation_id):
            return False, 0
        if action["kind"] != "retrieve":
            if operation_id in seen_operations:
                return False, 0
            seen_operations.add(operation_id)
        action_path = action.get("rawResponsePath")
        action_hash = action.get("rawResponseSha256")
        if action_path not in artifact_documents or not isinstance(action_hash, str) or not SHA256_RE.fullmatch(action_hash):
            return False, 0
        pinned = next((entry for entry in artifacts if entry.get("path") == action_path), None)
        if not pinned or pinned.get("sha256") != action_hash:
            return False, 0
    return True, len(actions)


def _verify_raw_release_references(root: Path, release: dict[str, Any], training: list[dict[str, Any]], ranked: list[dict[str, Any]], execution_hash: str) -> bool:
    expected: list[dict[str, Any]] = [
        {"kind": "feasibility", "path": release.get("manifest", {}).get("feasibilityEvidence", {}).get("path"),
         "sha256": release.get("manifest", {}).get("feasibilityEvidence", {}).get("sha256")},
        {"kind": "difficulty_review", "path": release.get("manifest", {}).get("difficultyReviewEvidence", {}).get("path"),
         "sha256": release.get("manifest", {}).get("difficultyReviewEvidence", {}).get("sha256")},
    ]
    cases = training + ranked
    for task_case in cases:
        expected.extend([
            {"kind": "initial_state", "taskId": task_case["taskId"], "mode": task_case["mode"],
             "path": task_case["initialStateEvidence"]["path"], "sha256": task_case["initialStateEvidence"]["sha256"]},
            {"kind": "reference_path", "taskId": task_case["taskId"], "mode": task_case["mode"],
             "path": task_case["referencePath"]["evidence"]["path"], "sha256": task_case["referencePath"]["evidence"]["sha256"]},
        ])
    actual = release.get("rawPathsHashes")
    if actual != expected:
        return False
    for entry in expected:
        _read_pinned_repo_json(root, entry["path"], entry["sha256"])
    for task_case in cases:
        verified, _ = _verify_reference_evidence(root, task_case, execution_hash)
        if not verified:
            return False
    return True


def _verify_release_database_snapshot(snapshot: Any) -> bool:
    if not isinstance(snapshot, dict):
        return False
    session = snapshot.get("session")
    if not isinstance(session, dict) or session.get("role") != "oid_observer" or session.get("readonly") != "on":
        return False
    tables = snapshot.get("tables")
    if not isinstance(tables, dict) or not tables:
        return False
    for table in tables.values():
        if not isinstance(table, dict) or not isinstance(table.get("present"), bool):
            return False
        if table["present"]:
            rows = table.get("rows")
            if not isinstance(rows, list) or table.get("rowCount") != len(rows) or table.get("rowsSha256") != _sha256_json(rows):
                return False
        elif table.get("rowCount") != 0:
            return False
    body = {key: snapshot[key] for key in ("session", "activePointer", "tables")}
    return snapshot.get("stateSha256") == _sha256_json(body)


def _rehash_release_candidate(candidate: dict[str, Any], *, identity_changed: bool = False) -> None:
    if identity_changed:
        candidate["executionIdentityHash"] = _sha256_json(candidate["executionIdentity"])
    for mode in ("training", "ranked"):
        for task_case in candidate["cases"][mode]:
            if identity_changed:
                task_case["executionIdentityHash"] = candidate["executionIdentityHash"]
            task_case["caseHash"] = _sha256_json(_without_key(task_case, "caseHash"))
    candidate["benchmarkHash"] = _sha256_json({
        "benchmarkVersion": candidate["benchmarkVersion"],
        "executionIdentityHash": candidate["executionIdentityHash"],
        "policyHash": candidate["policyHash"],
        "trainingCaseHashes": [{"taskId": row["taskId"], "caseHash": row["caseHash"]} for row in candidate["cases"]["training"]],
        "rankedCaseHashes": [{"taskId": row["taskId"], "caseHash": row["caseHash"]} for row in candidate["cases"]["ranked"]],
    })
    candidate["manifestHash"] = _sha256_json(_without_key(candidate, "manifestHash"))


def _replace_candidate_state(task_case: dict[str, Any], *, delivered: list[str] | None = None,
                             fulfilled: list[str] | None = None, balances: list[dict[str, Any]] | None = None) -> bool:
    state = task_case["initialState"]
    projection = {
        "balances": balances if balances is not None else state["balances"],
        "allowances": state["allowances"],
        "deliveredComponentIds": delivered if delivered is not None else state["deliveredComponentIds"],
        "fulfilledObligationIds": fulfilled if fulfilled is not None else state["fulfilledObligationIds"],
    }
    updated = _state_projection(projection)
    if updated is None:
        return False
    state.clear()
    state.update({"stateSha256": _sha256_json(updated), **updated})
    task_case["referencePath"]["initialStateSha256"] = state["stateSha256"]
    return True


def _expected_release_candidate(base_manifest: dict[str, Any], variant_id: str) -> tuple[dict[str, Any], str] | None:
    candidate = deepcopy(base_manifest)
    ranked = candidate["cases"]["ranked"]
    training = candidate["cases"]["training"]
    u1_index = next((i for i, row in enumerate(ranked) if row.get("taskId") == "U1"), -1)
    if u1_index < 0:
        return None
    identity_changed = False
    try:
        if variant_id == "placeholder":
            row = next(row for row in ranked if row["taskId"] == "M1")
            row["caseId"] = f"{row['caseId'][:96]}-placeholder"
        elif variant_id == "wrong_block_identity":
            identity = candidate["executionIdentity"]
            shifted = str(int(identity["sourceBlockNumber"]) + 1)
            identity["sourceBlockNumber"] = shifted
            identity["localForkBlockNumber"] = shifted
            for contract in identity["contracts"]:
                contract["blockNumber"] = shifted
            identity_changed = True
        elif variant_id == "wrong_contract_code_identity":
            contract = next(row for row in candidate["executionIdentity"]["contracts"] if row["contractId"] == "pool")
            code_hash = contract["codeHash"]
            contract["codeHash"] = ("1" if code_hash[0] == "0" else "0") + code_hash[1:]
            identity_changed = True
        elif variant_id == "initially_satisfied_paid_case":
            row = next(row for row in ranked if row["taskId"] == "M1")
            if not _replace_candidate_state(row, delivered=[*row["initialState"]["deliveredComponentIds"], row["objective"]["component"]["componentId"]]):
                return None
        elif variant_id == "initially_fulfilled_payout_obligation":
            row = next(row for row in ranked if row["taskId"] == "H2")
            if not _replace_candidate_state(row, fulfilled=[*row["initialState"]["fulfilledObligationIds"], row["objective"]["obligations"][0]["obligationId"]]):
                return None
        elif variant_id == "missing_reference_evidence":
            row = next(row for row in training if row["taskId"] == "S1")
            row["referencePath"]["evidence"]["path"] += ".missing-bts-reference"
        elif variant_id == "no_qualifying_catalog_offer":
            next(row for row in ranked if row["taskId"] == "S3")["objective"]["required"]["requiredDataType"] = "bts-no-qualifying-data-type"
        elif variant_id == "empty_u1_component_set":
            ranked[u1_index]["objective"]["requiredComponents"] = []
        elif variant_id == "duplicate_u1_component":
            values = ranked[u1_index]["objective"]["requiredComponents"]
            ranked[u1_index]["objective"]["requiredComponents"] = [values[0], deepcopy(values[0])]
        elif variant_id == "incomplete_u1_component_validator":
            validator = ranked[u1_index]["objective"]["requiredComponents"][0]["validator"]
            predicate_field = validator["predicates"][0]["field"]
            validator["requiredFields"] = [row for row in validator["requiredFields"] if row["name"] != predicate_field]
        elif variant_id == "empty_u1_allocation_asset_set":
            ranked[u1_index]["objective"]["allocationAssets"] = []
        elif variant_id == "duplicate_u1_allocation_asset":
            values = ranked[u1_index]["objective"]["allocationAssets"]
            ranked[u1_index]["objective"]["allocationAssets"] = [values[0], deepcopy(values[0])]
        elif variant_id == "fewer_than_two_u1_payout_obligations":
            values = ranked[u1_index]["objective"]["payoutObligations"]
            ranked[u1_index]["objective"]["payoutObligations"] = values[:1]
        elif variant_id == "duplicate_u1_payout_obligation":
            values = ranked[u1_index]["objective"]["payoutObligations"]
            values[1] = deepcopy(values[0])
        elif variant_id == "empty_u1_temporary_spender_set":
            ranked[u1_index]["objective"]["temporarySpenderScope"] = []
        elif variant_id == "duplicate_u1_temporary_spender":
            values = ranked[u1_index]["objective"]["temporarySpenderScope"]
            ranked[u1_index]["objective"]["temporarySpenderScope"] = [values[0], deepcopy(values[0])]
        elif variant_id == "initially_satisfied_u1_allocation":
            target = ranked[u1_index]
            assets = target["objective"]["allocationAssets"]
            total_usdc_value = 100_000_000
            amounts: dict[str, str] = {}
            for item in assets:
                numerator = int(item["usdcBaseUnitsPerAssetBaseUnit"]["numerator"])
                denominator = int(item["usdcBaseUnitsPerAssetBaseUnit"]["denominator"])
                target_value = total_usdc_value * int(item["targetShareBps"]) // 10_000
                amount = target_value * denominator // numerator
                if amount < 0 or (int(item["targetShareBps"]) > 0 and amount == 0) or len(str(amount)) > 78:
                    return None
                amounts[item["assetId"]] = str(amount)
            balances = [row for row in target["initialState"]["balances"]
                        if not (row["account"] == "participant" and row["assetId"] in amounts)]
            balances.extend({"account": "participant", "assetId": asset_id, "amountUnits": units} for asset_id, units in amounts.items())
            if not _replace_candidate_state(target, balances=balances) or not _u1_allocation_satisfied(target):
                return None
        else:
            return None
        _rehash_release_candidate(candidate, identity_changed=identity_changed)
    except (KeyError, IndexError, StopIteration, TypeError, ValueError, ZeroDivisionError):
        return None
    return candidate, RELEASE_VARIANT_REQUIREMENTS[variant_id][0]


def _variant_matches(candidate: Any, variant: Any, base_manifest: dict[str, Any], snapshots: dict[str, dict[str, Any]]) -> bool:
    if not isinstance(variant, dict):
        return False
    variant_id = variant.get("id")
    expected_spec = RELEASE_VARIANT_REQUIREMENTS.get(variant_id)
    expected = _expected_release_candidate(base_manifest, variant_id) if isinstance(variant_id, str) else None
    candidate_manifest = variant.get("candidateManifest")
    if not expected_spec or not expected or not isinstance(candidate_manifest, dict):
        return False
    expected_candidate, expected_path = expected
    blockers = variant.get("observedBlockers")
    if not isinstance(blockers, list):
        return False
    blocker_pairs = {(row.get("code"), row.get("subject")) for row in blockers if isinstance(row, dict)}
    if not all(any(code == row_code and isinstance(subject, str) and subject.startswith(prefix)
                   for row_code, subject in blocker_pairs) for code, prefix in expected_spec[1]):
        return False
    before_hash = variant.get("databaseStateSha256Before")
    after_hash = variant.get("databaseStateSha256After")
    return bool(
        variant.get("status") == "verified"
        and variant.get("candidateHash") == candidate_manifest.get("manifestHash")
        and candidate_manifest == expected_candidate
        and variant.get("mutationPath") == expected_path
        and variant.get("databaseUnchanged") is True
        and isinstance(before_hash, str) and before_hash == after_hash
        and before_hash in snapshots
        and variant.get("activationErrorCode") is None
    )


def _u1_allocation_satisfied(task_case: dict[str, Any]) -> bool:
    objective = task_case.get("objective", {})
    assets = objective.get("allocationAssets")
    if not isinstance(assets, list) or not assets:
        return False
    balances = task_case.get("initialState", {}).get("balances", [])
    values: dict[str, Fraction] = {}
    try:
        for asset in assets:
            amount = sum(int(row["amountUnits"]) for row in balances if row.get("account") == "participant" and row.get("assetId") == asset["assetId"])
            rate = asset["usdcBaseUnitsPerAssetBaseUnit"]
            values[asset["assetId"]] = Fraction(amount * int(rate["numerator"]), int(rate["denominator"]))
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return False
    total = sum(values.values(), Fraction(0, 1))
    if total <= 0:
        return False
    for asset in assets:
        actual_bps = values[asset["assetId"]] * 10000 / total
        if abs(actual_bps - int(asset["targetShareBps"])) > int(asset["toleranceBps"]):
            return False
    return True


def _derive_release_facts(scenario_id: str, capture: dict[str, Any], repository_root: Path) -> dict[str, bool]:
    _, contract, _ = _load_contract_sources()
    contract_row = contract["protected_scenarios"][scenario_id]
    facts = {name: False for name in (*contract_row["required_observations"], *contract_row["negative_variants"])}
    release = capture.get("release") if isinstance(capture.get("release"), dict) else {}
    manifest = release.get("manifest")
    manifest_ok, training, ranked = _verify_task_manifest(manifest)
    if not manifest_ok:
        return facts
    identity = manifest["executionIdentity"]
    execution_hash = _sha256_json(identity)
    facts["training_ids_and_weights"] = all(row.get("taskWeight") == TASK_WEIGHTS[row["taskId"]] for row in training)
    facts["release_identity"] = isinstance(manifest.get("releaseIdentity"), str) and bool(manifest["releaseIdentity"].strip())
    facts["manifest_hash"] = manifest.get("manifestHash") == _sha256_json(_without_key(manifest, "manifestHash"))
    facts["case_count"] = len(training) == 3 and len(ranked) == 12
    positive = capture.get("positiveActivation") if isinstance(capture.get("positiveActivation"), dict) else {}
    facts["release_hash"] = bool(
        positive.get("status") == "validated"
        and positive.get("manifestHash") == manifest.get("manifestHash")
        and release.get("releaseIdentity") == manifest.get("releaseIdentity")
        and release.get("manifestHash") == manifest.get("manifestHash")
        and release.get("benchmarkVersion") == manifest.get("benchmarkVersion")
        and release.get("benchmarkHash") == manifest.get("benchmarkHash")
        and release.get("policyHash") == manifest.get("policyHash")
    )
    facts["source_environment_hash"] = bool(
        SHA256_RE.fullmatch(str(identity.get("environmentManifestSha256", "")))
        and release.get("sourceEnvironmentHash") == identity.get("environmentManifestSha256")
        and release.get("executionIdentityHash") == execution_hash
        and release.get("sourceChainId") == identity.get("sourceChainId")
        and release.get("sourceBlockNumber") == identity.get("sourceBlockNumber")
        and release.get("sourceBlockHash") == identity.get("sourceBlockHash")
        and release.get("localChainId") == identity.get("localChainId")
        and release.get("localForkBlockNumber") == identity.get("localForkBlockNumber")
    )
    summary_cases = release.get("caseHashes")
    expected_summary = [{
        "mode": row["mode"], "taskId": row["taskId"], "caseId": row["caseId"],
        "caseHash": row["caseHash"], "rubricHash": row["rubricHash"], "taskWeight": row["taskWeight"],
        "referenceActionCount": row["referencePath"]["actionCount"],
        "referenceEvidence": {
            "path": row["referencePath"]["evidence"]["path"],
            "sha256": row["referencePath"]["evidence"]["sha256"],
        },
    } for row in training + ranked]
    facts["case_hashes"] = summary_cases == expected_summary and all(
        row.get("caseHash") == _sha256_json(_without_key(row, "caseHash")) for row in training + ranked)
    facts["case_hash"] = facts["case_hashes"]
    facts["typed_parameters"] = bool(
        manifest.get("pricing", {}).get("precision") == 6
        and manifest.get("pricing", {}).get("trainingRounding") == "ceil_once_per_request"
        and manifest.get("deadlines", {}).get("taskTimeoutSeconds", 0) > 0
        and manifest.get("deadlines", {}).get("trainingRunTimeoutSeconds", 0) > 0
        and manifest.get("deadlines", {}).get("rankedRunTimeoutSeconds", 0) > 0
        and all(_valid_case_shape(row, "training", row["taskId"], execution_hash) for row in training)
        and all(_valid_case_shape(row, "ranked", row["taskId"], execution_hash) for row in ranked)
    )
    try:
        facts["raw_paths_hashes"] = _verify_raw_release_references(repository_root, release, training, ranked, execution_hash)
        facts["reference_path_lengths"] = bool(
            facts["raw_paths_hashes"]
            and release.get("verifier", {}).get("referencePathCount") == 15
            and release.get("verifier", {}).get("verifiedReferencePathCount") == 15
            and all(_verify_reference_evidence(repository_root, row, execution_hash)[1] == row["referencePath"]["actionCount"]
                    for row in training + ranked)
        )
    except (AssertionError, OSError, ValueError, KeyError, TypeError):
        facts["raw_paths_hashes"] = False
        facts["reference_path_lengths"] = False

    database = capture.get("database") if isinstance(capture.get("database"), dict) else {}
    snapshots_raw = database.get("snapshots")
    snapshots: dict[str, dict[str, Any]] = {}
    if isinstance(snapshots_raw, list):
        for snapshot in snapshots_raw:
            if _verify_release_database_snapshot(snapshot):
                snapshots[snapshot["stateSha256"]] = snapshot
    before = database.get("before")
    before_hash = before.get("stateSha256") if isinstance(before, dict) else None
    before_ok = bool(_verify_release_database_snapshot(before) and before_hash in snapshots)
    active = before.get("activePointer") if isinstance(before, dict) else None
    active_match = bool(isinstance(active, list) and len(active) == 1
                        and active[0].get("release_identity") == manifest.get("releaseIdentity")
                        and active[0].get("manifest_hash") == manifest.get("manifestHash"))
    variants_raw = capture.get("variants")
    variants = {row.get("id"): row for row in variants_raw if isinstance(row, dict)} if isinstance(variants_raw, list) else {}
    unique_variants = bool(
        isinstance(variants_raw, list)
        and len(variants) == len(variants_raw)
        and set(variants) == set(RELEASE_VARIANT_REQUIREMENTS)
    )
    variant_results = {
        variant_id: _variant_matches(None, variants.get(variant_id), manifest, snapshots)
        for variant_id in RELEASE_VARIANT_REQUIREMENTS
    }
    database_unchanged = bool(
        before_ok and active_match and unique_variants
        and all(row.get("databaseUnchanged") is True and row.get("databaseStateSha256Before") == before_hash
                and row.get("databaseStateSha256After") == before_hash for row in variants.values())
        and all(snapshot_hash == before_hash for snapshot_hash in snapshots)
    )
    verifier = release.get("verifier") if isinstance(release.get("verifier"), dict) else {}
    facts["typed_parameters"] = facts["typed_parameters"] and verifier.get("difficultyStatus") == "approved"
    coverage = capture.get("coverage") if isinstance(capture.get("coverage"), dict) else {}
    negative_map = SC001_NEGATIVE_MAP if scenario_id == "BTS-SC-001" else SC002_NEGATIVE_MAP
    scenario_variant_ids = {variant_id for variant_ids in negative_map.values() for variant_id in variant_ids}
    scenario_variants_verified = all(variant_results.get(variant_id) is True for variant_id in scenario_variant_ids)
    full_variant_coverage = bool(
        coverage.get("requested") == len(RELEASE_VARIANT_REQUIREMENTS)
        and coverage.get("observed") == len(RELEASE_VARIANT_REQUIREMENTS)
        and coverage.get("notRun") == 0 and coverage.get("failed") == 0
        and all(variant_results.values())
    )
    facts["cutoff"] = bool(database_unchanged and scenario_variants_verified)
    if scenario_id == "BTS-SC-002":
        facts["cutoff"] = facts["cutoff"] and full_variant_coverage
    for required_name, variant_ids in negative_map.items():
        facts[required_name] = bool(unique_variants and all(variant_results.get(name) is True for name in variant_ids))

    u1 = next(row for row in ranked if row["taskId"] == "U1")
    objective = u1["objective"]
    u1_summary = release.get("u1") if isinstance(release.get("u1"), dict) else {}
    components = objective.get("requiredComponents", [])
    component_ids = [row.get("componentId") for row in components if isinstance(row, dict)]
    allocation = objective.get("allocationAssets", [])
    allocation_ids = [row.get("assetId") for row in allocation if isinstance(row, dict)]
    obligations = objective.get("payoutObligations", [])
    obligation_ids = [row.get("obligationId") for row in obligations if isinstance(row, dict)]
    spenders = objective.get("temporarySpenderScope", [])
    spender_keys = [{"owner": row.get("owner"), "tokenAssetId": row.get("tokenAssetId"), "spender": row.get("spender")} for row in spenders if isinstance(row, dict)]
    if scenario_id == "BTS-SC-002":
        facts["u1_component_ids"] = bool(component_ids and len(set(component_ids)) == len(component_ids) and u1_summary.get("componentIds") == component_ids)
        facts["u1_component_validator_specs"] = bool(all(_valid_component(row) for row in components)
            and u1_summary.get("componentValidatorSpecs") == [
                {"componentId": row["componentId"], "resourceId": row["resourceId"],
                 "sourceIds": row["sourceIds"], "validator": row["validator"]} for row in components])
        facts["u1_allocation_asset_ids"] = bool(allocation_ids and len(set(allocation_ids)) == len(allocation_ids)
            and u1_summary.get("allocationAssets") == allocation)
        facts["u1_payout_obligation_ids"] = bool(len(obligation_ids) >= 2 and len(set(obligation_ids)) == len(obligation_ids)
            and u1_summary.get("payoutObligations") == obligations)
        facts["u1_temporary_allowance_keys"] = bool(spender_keys and len({(row["owner"].lower(), row["tokenAssetId"], row["spender"].lower()) for row in spender_keys}) == len(spender_keys)
            and u1_summary.get("temporarySpenderKeys") == [{"owner": row["owner"], "tokenAssetId": row["tokenAssetId"], "spender": row["spender"]} for row in spenders])
        initial_variant = variants.get("initially_satisfied_u1_allocation")
        candidate = initial_variant.get("candidateManifest") if isinstance(initial_variant, dict) else None
        candidate_u1 = next((row for row in candidate.get("cases", {}).get("ranked", []) if row.get("taskId") == "U1"), {}) if isinstance(candidate, dict) else {}
        facts["initially_satisfied_u1_allocation_blocks_release_before_admission_or_charge"] = bool(
            variant_results.get("initially_satisfied_u1_allocation") is True
            and _u1_allocation_satisfied(candidate_u1)
            and database_unchanged
        )
        facts["admission_charge_absence"] = database_unchanged and full_variant_coverage
    return facts


def _fraction_pair(value: Any) -> Fraction | None:
    if not isinstance(value, dict) or not _valid_units(value.get("numerator")) or not _valid_units(value.get("denominator"), positive=True):
        return None
    return Fraction(int(value["numerator"]), int(value["denominator"]))


def _fraction_json(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _known_result(result: Any, task_id: str) -> Fraction | None:
    if not isinstance(result, dict) or result.get("status") != "known" or result.get("taskId") != task_id:
        return None
    if result.get("outcome") not in {"passed", "partial", "failed"} or result.get("unknownReasons") != []:
        return None
    credit = _fraction_pair(result.get("credit"))
    if credit is None or credit < 0 or credit > 1:
        return None
    if result["outcome"] == "passed" and credit != 1:
        return None
    if result["outcome"] == "failed" and credit != 0:
        return None
    if result["outcome"] == "partial" and credit in {Fraction(0), Fraction(1)}:
        return None
    if result.get("mandatoryViolation") is not None and (result["outcome"] != "failed" or credit != 0):
        return None
    return credit


def _expected_ranked_aggregate(manifest: dict[str, Any], evaluations: list[dict[str, Any]]) -> dict[str, Any] | None:
    cases = manifest.get("cases", {}).get("ranked", [])
    if len(cases) != len(TASK_IDS) or len(evaluations) != len(TASK_IDS):
        return None
    total = Fraction(0)
    tier_totals = {level: Fraction(0) for level in ("simple", "medium", "hard", "ultra")}
    tier_weights = {level: 0 for level in tier_totals}
    proofs = []
    for index, task_id in enumerate(TASK_IDS):
        case = cases[index]
        evaluation = evaluations[index]
        proof = None
        # The coordinator's aggregate proof is retained in the database; this
        # independent score computation uses only the release weights and the
        # full result JSON from the read-only evaluator rows.
        credit = _known_result(evaluation.get("result_json"), task_id)
        if credit is None or evaluation.get("task_index") != index or evaluation.get("task_id") != task_id:
            return None
        weight = TASK_WEIGHTS[task_id]
        weighted_credit = credit * weight
        total += weighted_credit
        level = TASK_LEVELS[task_id]
        tier_totals[level] += weighted_credit
        tier_weights[level] += weight
        proofs.append({
            "taskIndex": index,
            "taskId": task_id,
            "caseHash": case["caseHash"],
            "rubricHash": case["rubricHash"],
            "inputHash": evaluation.get("input_hash"),
            "resultHash": evaluation.get("result_hash"),
            "fenceEvidenceHash": None,
            "result": evaluation["result_json"],
        })
    if sum(TASK_WEIGHTS.values()) != 26 or any(weight == 0 for weight in tier_weights.values()):
        return None
    overall = _fraction_json(total * 100 / 26)
    tiers = {level: _fraction_json(tier_totals[level] * 100 / tier_weights[level]) for level in tier_totals}
    return {"overall": overall, "tiers": tiers, "taskProofs": proofs}


def _verify_ranked_snapshot_integrity(snapshot: Any) -> bool:
    if not isinstance(snapshot, dict):
        return False
    observer = snapshot.get("observer")
    if not isinstance(observer, dict) or observer.get("role") != "oid_observer" or observer.get("readOnly") != "on":
        return False
    return snapshot.get("sha256") == _sha256_json(_without_key(snapshot, "sha256"))


def _ranked_snapshot_map(capture: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = capture.get("databaseSnapshots")
    if not isinstance(raw, dict):
        return {}
    return {name: snapshot for name, snapshot in raw.items() if _verify_ranked_snapshot_integrity(snapshot)}


def _same_snapshot(snapshots: dict[str, dict[str, Any]], left: str, right: str) -> bool:
    a, b = snapshots.get(left), snapshots.get(right)
    return bool(a and b and a.get("sha256") == b.get("sha256")
                and _canonical_json(_without_key(a, "sha256")) == _canonical_json(_without_key(b, "sha256")))


def _verify_ranked_raw_references(root: Path, run_id: str, evaluations: Any) -> bool:
    if not isinstance(evaluations, list) or len(evaluations) != len(TASK_IDS):
        return False
    prefix = "artifacts/runs/owner-identity-bef-task-coordinator/"
    for index, evaluation in enumerate(evaluations):
        if not isinstance(evaluation, dict) or evaluation.get("task_index") != index or evaluation.get("task_id") != TASK_IDS[index]:
            return False
        refs = evaluation.get("evidence_references")
        if not isinstance(refs, list) or not refs:
            return False
        seen: set[str] = set()
        for reference in refs:
            if not isinstance(reference, dict) or reference.get("boundary") != "actual_tool_http_x402_local_evm_application_store":
                return False
            relative = reference.get("path")
            if not isinstance(relative, str) or not relative.startswith(prefix) or relative in seen:
                return False
            seen.add(relative)
            rest = relative[len(prefix):].split("/")
            if len(rest) == 4 and rest[0] == "observation":
                if rest[1] != run_id or rest[2] != TASK_IDS[index] or not re.fullmatch(r"[0-9a-f]{64}\.json", rest[3]):
                    return False
            elif len(rest) == 2 and rest[0] in {"action", "preparation"}:
                if not re.fullmatch(r"[0-9a-f-]{36}-[0-9a-f-]{36}\.json", rest[1]):
                    return False
            else:
                return False
            _read_pinned_repo_json(root, relative, reference.get("sha256"))
    return True


def _derive_ranked_facts(capture: dict[str, Any], repository_root: Path) -> dict[str, bool]:
    _, contract, _ = _load_contract_sources()
    row = contract["protected_scenarios"]["BTS-SC-009"]
    facts = {name: False for name in (*row["required_observations"], *row["negative_variants"])}
    manifest = capture.get("release", {}).get("manifest") if isinstance(capture.get("release"), dict) else None
    manifest_ok, _training, ranked = _verify_task_manifest(manifest)
    if not manifest_ok:
        return facts
    snapshots = _ranked_snapshot_map(capture)
    before = snapshots.get("before")
    if not before:
        return facts
    run_rows = before.get("run")
    if not isinstance(run_rows, list) or len(run_rows) != 1:
        return facts
    run = run_rows[0]
    run_id = run.get("id")
    owner_id, agent_id = run.get("owner_id"), run.get("agent_id")
    evaluations = before.get("evaluations")
    tasks = before.get("tasks")
    bundles = before.get("observationBundles")
    events = before.get("events")
    aggregate_rows = before.get("rankedResults")
    handoffs = before.get("rankedHandoffs")
    releases_ok = bool(
        run.get("mode") == "ranked" and run.get("status") == "completed"
        and run.get("task_ids") == list(TASK_IDS)
        and run.get("release_identity") == manifest.get("releaseIdentity")
        and run.get("manifest_hash") == manifest.get("manifestHash")
        and run.get("benchmark_version") == manifest.get("benchmarkVersion")
        and run.get("benchmark_hash") == manifest.get("benchmarkHash")
        and run.get("policy_hash") == manifest.get("policyHash")
    )
    if not all(isinstance(value, list) for value in (evaluations, tasks, bundles, events, aggregate_rows, handoffs)):
        return facts
    evaluations = [value for value in evaluations if isinstance(value, dict)]
    tasks = [value for value in tasks if isinstance(value, dict)]
    bundles = [value for value in bundles if isinstance(value, dict)]
    outcomes_good = releases_ok and len(evaluations) == len(tasks) == len(bundles) == 12
    case_hash_ok = outcomes_good
    cutoff_ok = outcomes_good
    for index, (task_id, evaluation, task, bundle, task_case) in enumerate(zip(TASK_IDS, evaluations, tasks, bundles, ranked, strict=True)):
        result = evaluation.get("result_json")
        credit = _known_result(result, task_id)
        if (evaluation.get("task_index") != index or evaluation.get("task_id") != task_id or credit is None
                or evaluation.get("result_status") != "known" or evaluation.get("outcome") != result.get("outcome")
                or evaluation.get("credit") != result.get("credit")
                or evaluation.get("case_hash") != task_case.get("caseHash")
                or evaluation.get("rubric_hash") != task_case.get("rubricHash")
                or evaluation.get("result_hash") != _sha256_json(result)):
            outcomes_good = False
        if (evaluation.get("case_hash") != task_case.get("caseHash")
                or evaluation.get("rubric_hash") != task_case.get("rubricHash")):
            case_hash_ok = False
        if (task.get("task_index") != index or task.get("task_id") != task_id
                or task.get("closure_status") != "closed" or not task.get("closure_id")
                or evaluation.get("closure_id") != task.get("closure_id")):
            outcomes_good = False
        if (bundle.get("task_index") != index or not SHA256_RE.fullmatch(str(bundle.get("bundle_hash", "")))
                or bundle.get("action_cutoff_sequence") != task.get("action_cutoff_sequence")
                or bundle.get("reconciled_action_sequence") != task.get("reconciled_action_sequence")):
            cutoff_ok = False
        try:
            if int(bundle.get("reconciled_action_sequence", -1)) < int(bundle.get("action_cutoff_sequence", 0)):
                cutoff_ok = False
        except (TypeError, ValueError):
            cutoff_ok = False
        if not SHA256_RE.fullmatch(str(evaluation.get("case_hash", ""))) or not SHA256_RE.fullmatch(str(evaluation.get("rubric_hash", ""))):
            case_hash_ok = False

    facts["twelve_graded_outcomes"] = outcomes_good
    facts["case_hash"] = case_hash_ok
    facts["cutoff"] = bool(
        cutoff_ok and all(_verify_ranked_snapshot_integrity(snapshot) for snapshot in snapshots.values())
        and all(_same_snapshot(snapshots, "before", name) for name in ("afterDenial", "afterRecovery") if name in snapshots)
    )
    try:
        facts["raw_paths_hashes"] = _verify_ranked_raw_references(repository_root, run_id, evaluations)
    except (AssertionError, OSError, ValueError, KeyError, TypeError):
        facts["raw_paths_hashes"] = False

    completed_events = [event for event in events if isinstance(event, dict) and event.get("event_type") == "run.completed"]
    eligible_events = [event for event in events if isinstance(event, dict) and event.get("event_type") == "run.ranked_eligible"]
    completion_event = completed_events[0] if len(completed_events) == 1 else {}
    completion_payload = completion_event.get("payload_json") if isinstance(completion_event.get("payload_json"), dict) else {}
    completion_hash_ok = bool(
        completion_event.get("source") == "coordinator"
        and completion_event.get("payload_hash") == _sha256_json(completion_payload)
        and completion_payload.get("runId") == run_id and completion_payload.get("mode") == "ranked"
        and isinstance(completion_payload.get("tasks"), list) and len(completion_payload["tasks"]) == 12
    )
    if completion_hash_ok:
        for index, task_event in enumerate(completion_payload["tasks"]):
            evaluation = evaluations[index]
            if (not isinstance(task_event, dict) or task_event.get("taskIndex") != index
                    or task_event.get("taskId") != TASK_IDS[index]
                    or task_event.get("inputHash") != evaluation.get("input_hash")
                    or task_event.get("resultHash") != evaluation.get("result_hash")
                    or not SHA256_RE.fullmatch(str(task_event.get("fenceEvidenceHash", "")))):
                completion_hash_ok = False
                break
    facts["coordinator_eligibility"] = bool(
        facts["twelve_graded_outcomes"] and completion_hash_ok and len(eligible_events) == 1
        and eligible_events[0].get("source") == "coordinator"
    )

    exact_aggregate = False
    aggregate = aggregate_rows[0].get("aggregate_json") if len(aggregate_rows) == 1 and isinstance(aggregate_rows[0], dict) else None
    if isinstance(aggregate, dict) and facts["twelve_graded_outcomes"]:
        proofs = aggregate.get("taskProofs")
        if isinstance(proofs, list) and len(proofs) == 12:
            proof_results_match = True
            for index, proof in enumerate(proofs):
                evaluation = evaluations[index]
                if (not isinstance(proof, dict) or proof.get("taskIndex") != index or proof.get("taskId") != TASK_IDS[index]
                        or proof.get("caseHash") != evaluation.get("case_hash") or proof.get("rubricHash") != evaluation.get("rubric_hash")
                        or proof.get("inputHash") != evaluation.get("input_hash") or proof.get("resultHash") != evaluation.get("result_hash")
                        or proof.get("result") != evaluation.get("result_json")
                        or proof.get("resultHash") != _sha256_json(proof.get("result"))
                        or not SHA256_RE.fullmatch(str(proof.get("fenceEvidenceHash", "")))):
                    proof_results_match = False
            if proof_results_match:
                recomputed = _expected_ranked_aggregate(manifest, evaluations)
                expected_body = {
                    "schemaVersion": "ranked-outcome-aggregate/v1",
                    "releaseIdentity": manifest["releaseIdentity"],
                    "manifestHash": manifest["manifestHash"],
                    "benchmarkVersion": manifest["benchmarkVersion"],
                    "benchmarkHash": manifest["benchmarkHash"],
                    "policyHash": manifest["policyHash"],
                    "overall": (recomputed or {}).get("overall"),
                    "tiers": (recomputed or {}).get("tiers"),
                    "taskProofs": proofs,
                }
                exact_aggregate = bool(
                    recomputed and aggregate == {**expected_body, "aggregateHash": _sha256_json(expected_body)}
                    and aggregate_rows[0].get("aggregate_hash") == aggregate.get("aggregateHash")
                    and aggregate.get("overall") == capture.get("rankedOutcome", {}).get("exactOverall")
                    and aggregate.get("tiers") == capture.get("rankedOutcome", {}).get("exactTiers")
                )
    facts["exact_aggregate"] = exact_aggregate

    version_rows = before.get("versionSnapshots")
    version = version_rows[0] if isinstance(version_rows, list) and len(version_rows) == 1 and isinstance(version_rows[0], dict) else {}
    version_json = version.get("snapshot_json")
    version_ok = bool(
        isinstance(version_json, dict) and version.get("snapshot_hash") == _sha256_json(version_json)
        and version_json.get("runId") == run_id and version_json.get("ownerId") == owner_id
        and version_json.get("agentId") == agent_id and version_json.get("schemaVersion") == "ranked-agent-version-snapshot/v1"
    )
    handoff = handoffs[0] if len(handoffs) == 1 and isinstance(handoffs[0], dict) else {}
    handoff_json = handoff.get("handoff_json")
    handoff_ok = bool(
        isinstance(handoff_json, dict) and handoff.get("handoff_hash") == _sha256_json(handoff_json)
        and handoff.get("aggregate_hash") == aggregate.get("aggregateHash") if isinstance(aggregate, dict) else False
    )
    if handoff_ok:
        handoff_ok = bool(
            handoff_json.get("runId") == run_id and handoff_json.get("ownerId") == owner_id
            and handoff_json.get("agentId") == agent_id and handoff_json.get("manifestHash") == manifest.get("manifestHash")
            and handoff_json.get("benchmarkVersion") == manifest.get("benchmarkVersion")
            and handoff_json.get("versionSnapshotHash") == version.get("snapshot_hash")
            and handoff_json.get("aggregateHash") == aggregate.get("aggregateHash")
            and handoff_json.get("completionEventHash") == completion_event.get("payload_hash")
            and handoff_json.get("taskProofs") == [
                {key: value for key, value in proof.items() if key != "result"} for proof in aggregate.get("taskProofs", [])]
        )
    eligible = eligible_events[0] if len(eligible_events) == 1 and isinstance(eligible_events[0], dict) else {}
    facts["coordinator_eligibility"] = bool(
        facts["coordinator_eligibility"] and version_ok and handoff_ok
        and eligible.get("payload_hash") == handoff.get("handoff_hash")
        and eligible.get("payload_json") == handoff_json
    )
    best = before.get("bestResults")
    facts["best_result_identity"] = bool(
        facts["coordinator_eligibility"] and isinstance(best, list) and len(best) == 1
        and best[0].get("run_id") == run_id and best[0].get("benchmark_version") == manifest.get("benchmarkVersion")
    )
    facts["handoff_deduplication"] = bool(
        facts["coordinator_eligibility"] and len(handoffs) == 1
        and len([event for event in eligible_events]) == 1
        and _same_snapshot(snapshots, "before", "afterCompletedRunReplay")
        and _same_snapshot(snapshots, "before", "afterRestartReplay")
    )
    reservations = before.get("reservations")
    holds = before.get("budgetHolds")
    ledger = before.get("rankedLedgerEntries")
    quote = run.get("quote_price_units")
    facts["no_extra_charge"] = bool(
        isinstance(reservations, list) and len(reservations) == 1 and reservations[0].get("state") == "debited"
        and str(reservations[0].get("amount_units")) == str(quote)
        and isinstance(holds, list) and len(holds) == 1 and holds[0].get("state") == "charged"
        and str(holds[0].get("amount_units")) == str(quote)
        and isinstance(ledger, list) and len(ledger) == 2
        and sorted(row.get("entry_type") for row in ledger if isinstance(row, dict)) == ["debit", "reserve"]
        and all(str(row.get("amount_units")) == str(quote) for row in ledger if isinstance(row, dict))
        and {row.get("operation_id") for row in ledger if isinstance(row, dict)} == {
            "runacc_" + str(run_id).replace("-", ""), "rundeb_" + str(run_id).replace("-", "")}
        and before.get("executionSlotCount") == 0
        and _same_snapshot(snapshots, "before", "afterCompletedRunReplay")
        and _same_snapshot(snapshots, "before", "afterForgedGrade")
        and _same_snapshot(snapshots, "before", "afterRestartReplay")
    )

    checks = {row.get("name"): row for row in capture.get("checks", []) if isinstance(row, dict)} if isinstance(capture.get("checks"), list) else {}
    replay_check = checks.get("completed_ranked_run_replay", {})
    forged_check = checks.get("agent_forged_score_denied", {})
    restart_check = checks.get("ranked_completion_replay_after_api_restart", {})
    unknown_check = checks.get("unknown_or_unavailable_evidence_reconstruction_denied", {})
    facts["duplicate_handoff"] = bool(
        replay_check.get("status") == "verified" and replay_check.get("unchanged") is True
        and _same_snapshot(snapshots, "before", "afterCompletedRunReplay")
    )
    facts["forged_credit"] = bool(
        forged_check.get("status") == "verified" and forged_check.get("actionOrGradeAccepted") is False
        and forged_check.get("httpStatus") in {400, 409, 422}
        and SHA256_RE.fullmatch(str(forged_check.get("requestSha256", "")))
        and SHA256_RE.fullmatch(str(forged_check.get("responseSha256", "")))
        and _same_snapshot(snapshots, "before", "afterForgedGrade")
    )
    facts["restart"] = bool(
        restart_check.get("status") == "verified" and restart_check.get("healthStatus") == 200
        and restart_check.get("replayed") is True
        and restart_check.get("ownerResults", {}).get("httpStatus") == 200
        and restart_check.get("ownerResults", {}).get("status") == "available"
        and len(restart_check.get("ownerResults", {}).get("tasks", [])) == 12
        and _same_snapshot(snapshots, "before", "afterRestartReplay")
    )
    unknown_gap = capture.get("unknownOutcomeGap") if isinstance(capture.get("unknownOutcomeGap"), dict) else {}
    unverified = capture.get("unverifiedVariants")
    # Replay denial after omitting a raw file is not a separately persisted
    # unknown task result. Keep this contract negative blocked until that exact
    # persisted-outcome path is genuinely exercised.
    facts["unknown_outcome"] = bool(
        unknown_check.get("status") == "verified"
        and unknown_gap.get("unverifiedVariants") == []
        and isinstance(unverified, list) and "distinct_persisted_unknown_task_outcome_without_a_new_ranked_run" not in unverified
    )
    return facts


def _blocked_gap(scenario_id: str, boundary_detail: str) -> str:
    if scenario_id == "BTS-SC-025":
        return (
            "positive owner launch/agent acceptance and pinned external-client evidence are absent; "
            "the existing launch-boundary capture is explicitly partial_blocked"
        )
    if scenario_id in {"BTS-SC-005", "BTS-SC-006", "BTS-SC-012", "BTS-SC-013", "BTS-SC-019"}:
        return (
            f"no per-scenario {boundary_detail} HTTP evidence bundle; the existing run-start integration "
            "uses synthetic readiness/fence ports and is not accepted as this environment gate"
        )
    return f"no per-scenario hash-pinned {boundary_detail} runtime evidence bundle is available"


def _reject_unverified_pass(scenario_id: str) -> None:
    if scenario_id not in PASSABLE_SCENARIOS:
        raise AssertionError(
            f"{scenario_id} cannot pass from manifest status or fixture/unit-model claims; "
            "a scenario-specific raw HTTP/PostgreSQL/executor verifier is not implemented"
        )


class BenchmarkTaskSuiteEvidenceCase:
    """Verify source-bound environment captures; missing boundaries stay blocked."""

    def __init__(self, scenario_id: str, proposal_row: dict[str, Any], contract_row: dict[str, Any]) -> None:
        self.scenario_id = scenario_id
        self.proposal_row = proposal_row
        self.contract_row = contract_row

    def setup(self, context: ScenarioContext) -> None:
        if context.scenario_id != self.scenario_id:
            raise AssertionError("BTS mapper and scenario identity differ")
        context.state["bts_boundary_detail"] = self.proposal_row["boundary_detail"]

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        getattr(self, "_execute_" + self.scenario_id.replace("-", "_"))(context)

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        getattr(self, "_verify_" + self.scenario_id.replace("-", "_"))(context)

    def _execute_evidence(self, context: ScenarioContext) -> None:
        loaded = _load_run(self.scenario_id)
        if loaded is None:
            pytest.skip("BLOCKED: missing actual " + self.proposal_row["boundary_detail"] + " scenario capture")
        manifest, artifacts = loaded
        context.state["bts_manifest"] = manifest
        context.state["bts_artifacts"] = artifacts
        if self.scenario_id in {"BTS-SC-001", "BTS-SC-002"}:
            capture = artifacts.get("runtime-capture.json")
            facts = _derive_release_facts(self.scenario_id, capture if isinstance(capture, dict) else {}, REPOSITORY_ROOT)
            context.state["bts_verified_facts"] = facts
        elif self.scenario_id == "BTS-SC-009":
            capture = artifacts.get("runtime-capture.json")
            facts = _derive_ranked_facts(capture if isinstance(capture, dict) else {}, REPOSITORY_ROOT)
            context.state["bts_verified_facts"] = facts
        else:
            facts = {}
        if manifest["status"] in {"blocked", "running"}:
            pytest.skip("BLOCKED: " + str(manifest.get("blockedReasonCode", "runtime capture incomplete")))
        if manifest["status"] != "passed":
            raise AssertionError("Actual BTS capture did not pass")
        if self.scenario_id not in PASSABLE_SCENARIOS:
            raise AssertionError(
                f"{self.scenario_id} cannot pass: its approved negative inventory is not completely covered by an independent raw-evidence verifier"
            )
        required = (*self.contract_row["required_observations"], *self.contract_row["negative_variants"])
        if any(facts.get(name) is not True for name in required):
            missing = [name for name in required if facts.get(name) is not True]
            raise AssertionError(f"{self.scenario_id} passed manifest is not supported by derived evidence: {','.join(missing)}")
        observations = manifest.get("observations")
        negatives = manifest.get("negativeVariants")
        if (not isinstance(observations, dict) or not isinstance(negatives, dict)
                or any(not isinstance(item, dict) or item.get("status") != "observed" for item in observations.values())
                or any(not isinstance(item, dict) or item.get("status") != "observed" for item in negatives.values())):
            raise AssertionError(f"{self.scenario_id} passed manifest has unobserved contract entries")

    def _verify_evidence(self, context: ScenarioContext) -> dict[str, bool]:
        if self.scenario_id not in PASSABLE_SCENARIOS:
            _reject_unverified_pass(self.scenario_id)
        facts = context.state.get("bts_verified_facts")
        if not isinstance(facts, dict):
            raise AssertionError("No independently derived BTS runtime facts")
        return facts

    def _execute_BTS_SC_001(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_001(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("training_ids_and_weights", facts.get("training_ids_and_weights") is True)
        context.check("release_identity", facts.get("release_identity") is True)
        context.check("manifest_hash", facts.get("manifest_hash") is True)
        context.check("case_count", facts.get("case_count") is True)
        context.check("release_hash", facts.get("release_hash") is True)
        context.check("case_hashes", facts.get("case_hashes") is True)
        context.check("source_environment_hash", facts.get("source_environment_hash") is True)
        context.check("typed_parameters", facts.get("typed_parameters") is True)
        context.check("reference_path_lengths", facts.get("reference_path_lengths") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_002(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_002(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("release_hash", facts.get("release_hash") is True)
        context.check("case_hashes", facts.get("case_hashes") is True)
        context.check("source_environment_hash", facts.get("source_environment_hash") is True)
        context.check("typed_parameters", facts.get("typed_parameters") is True)
        context.check("reference_path_lengths", facts.get("reference_path_lengths") is True)
        context.check("u1_component_ids", facts.get("u1_component_ids") is True)
        context.check("u1_component_validator_specs", facts.get("u1_component_validator_specs") is True)
        context.check("u1_allocation_asset_ids", facts.get("u1_allocation_asset_ids") is True)
        context.check("u1_payout_obligation_ids", facts.get("u1_payout_obligation_ids") is True)
        context.check("u1_temporary_allowance_keys", facts.get("u1_temporary_allowance_keys") is True)
        context.check("admission_charge_absence", facts.get("admission_charge_absence") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)
        context.check("initially_satisfied_u1_allocation_blocks_release_before_admission_or_charge", facts.get("initially_satisfied_u1_allocation_blocks_release_before_admission_or_charge") is True)

    def _execute_BTS_SC_003(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_003(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("singleton_quotes_micro_usdc", facts.get("singleton_quotes_micro_usdc") is True)
        context.check("full_bundle_quote_micro_usdc", facts.get("full_bundle_quote_micro_usdc") is True)
        context.check("selected_ids", facts.get("selected_ids") is True)
        context.check("open_weight_sum", facts.get("open_weight_sum") is True)
        context.check("integer_quote", facts.get("integer_quote") is True)
        context.check("reservation_identity", facts.get("reservation_identity") is True)
        context.check("source_allocation", facts.get("source_allocation") is True)
        context.check("closed_payload_absent", facts.get("closed_payload_absent") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_004(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_004(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("selected_ids", facts.get("selected_ids") is True)
        context.check("open_weight_sum", facts.get("open_weight_sum") is True)
        context.check("integer_quote", facts.get("integer_quote") is True)
        context.check("reservation_identity", facts.get("reservation_identity") is True)
        context.check("source_allocation", facts.get("source_allocation") is True)
        context.check("closed_payload_absent", facts.get("closed_payload_absent") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_005(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_005(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("cutoff_sequence", facts.get("cutoff_sequence") is True)
        context.check("original_receipts", facts.get("original_receipts") is True)
        context.check("final_state", facts.get("final_state") is True)
        context.check("historical_violations", facts.get("historical_violations") is True)
        context.check("cost_components", facts.get("cost_components") is True)
        context.check("exact_credit_or_unknown", facts.get("exact_credit_or_unknown") is True)
        context.check("reconstruction_comparison", facts.get("reconstruction_comparison") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_006(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_006(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("cutoff_sequence", facts.get("cutoff_sequence") is True)
        context.check("original_receipts", facts.get("original_receipts") is True)
        context.check("final_state", facts.get("final_state") is True)
        context.check("historical_violations", facts.get("historical_violations") is True)
        context.check("cost_components", facts.get("cost_components") is True)
        context.check("exact_credit_or_unknown", facts.get("exact_credit_or_unknown") is True)
        context.check("reconstruction_comparison", facts.get("reconstruction_comparison") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_007(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_007(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("current_closed_training_ids", facts.get("current_closed_training_ids") is True)
        context.check("current_open_training_ids", facts.get("current_open_training_ids") is True)
        context.check("issued_conditions", facts.get("issued_conditions") is True)
        context.check("feedback_release_state", facts.get("feedback_release_state") is True)
        context.check("owner_binding", facts.get("owner_binding") is True)
        context.check("projection_fields", facts.get("projection_fields") is True)
        context.check("rendered_payload", facts.get("rendered_payload") is True)
        context.check("cache_scope", facts.get("cache_scope") is True)
        context.check("no_closed_fields", facts.get("no_closed_fields") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_008(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_008(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("issued_conditions", facts.get("issued_conditions") is True)
        context.check("feedback_release_state", facts.get("feedback_release_state") is True)
        context.check("owner_binding", facts.get("owner_binding") is True)
        context.check("projection_fields", facts.get("projection_fields") is True)
        context.check("rendered_payload", facts.get("rendered_payload") is True)
        context.check("cache_scope", facts.get("cache_scope") is True)
        context.check("no_closed_fields", facts.get("no_closed_fields") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_009(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_009(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("twelve_graded_outcomes", facts.get("twelve_graded_outcomes") is True)
        context.check("coordinator_eligibility", facts.get("coordinator_eligibility") is True)
        context.check("exact_aggregate", facts.get("exact_aggregate") is True)
        context.check("best_result_identity", facts.get("best_result_identity") is True)
        context.check("handoff_deduplication", facts.get("handoff_deduplication") is True)
        context.check("no_extra_charge", facts.get("no_extra_charge") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_010(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_010(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("selected_parameters", facts.get("selected_parameters") is True)
        context.check("observed_learning_effect", facts.get("observed_learning_effect") is True)
        context.check("scope_denials", facts.get("scope_denials") is True)
        context.check("no_foreign_effect", facts.get("no_foreign_effect") is True)
        context.check("real_ledger_unchanged", facts.get("real_ledger_unchanged") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_011(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_011(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("principal_delta", facts.get("principal_delta") is True)
        context.check("native_reserve", facts.get("native_reserve") is True)
        context.check("transfer_receipt", facts.get("transfer_receipt") is True)
        context.check("exact_credit", facts.get("exact_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_012(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_012(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("principal_delta", facts.get("principal_delta") is True)
        context.check("native_reserve", facts.get("native_reserve") is True)
        context.check("transfer_receipt", facts.get("transfer_receipt") is True)
        context.check("exact_credit", facts.get("exact_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_013(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_013(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("observed_requirements", facts.get("observed_requirements") is True)
        context.check("structured_answer", facts.get("structured_answer") is True)
        context.check("complete_no_effect_interval", facts.get("complete_no_effect_interval") is True)
        context.check("group_credit", facts.get("group_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_014(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_014(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("observed_requirements", facts.get("observed_requirements") is True)
        context.check("structured_answer", facts.get("structured_answer") is True)
        context.check("complete_no_effect_interval", facts.get("complete_no_effect_interval") is True)
        context.check("group_credit", facts.get("group_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_015(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_015(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("catalog_hash", facts.get("catalog_hash") is True)
        context.check("selected_offer", facts.get("selected_offer") is True)
        context.check("predicate_results", facts.get("predicate_results") is True)
        context.check("complete_no_effect_interval", facts.get("complete_no_effect_interval") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_016(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_016(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("catalog_hash", facts.get("catalog_hash") is True)
        context.check("selected_offer", facts.get("selected_offer") is True)
        context.check("predicate_results", facts.get("predicate_results") is True)
        context.check("complete_no_effect_interval", facts.get("complete_no_effect_interval") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_017(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_017(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("initial_allowance", facts.get("initial_allowance") is True)
        context.check("final_allowance", facts.get("final_allowance") is True)
        context.check("unrelated_history", facts.get("unrelated_history") is True)
        context.check("revoke_receipt", facts.get("revoke_receipt") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_018(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_018(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("initial_allowance", facts.get("initial_allowance") is True)
        context.check("final_allowance", facts.get("final_allowance") is True)
        context.check("unrelated_history", facts.get("unrelated_history") is True)
        context.check("revoke_receipt", facts.get("revoke_receipt") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_019(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_019(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("offer_authorization", facts.get("offer_authorization") is True)
        context.check("settlement_receipt", facts.get("settlement_receipt") is True)
        context.check("token_effect", facts.get("token_effect") is True)
        context.check("delivery_hash", facts.get("delivery_hash") is True)
        context.check("operating_expense", facts.get("operating_expense") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_020(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_020(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("offer_authorization", facts.get("offer_authorization") is True)
        context.check("settlement_receipt", facts.get("settlement_receipt") is True)
        context.check("token_effect", facts.get("token_effect") is True)
        context.check("delivery_hash", facts.get("delivery_hash") is True)
        context.check("operating_expense", facts.get("operating_expense") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_021(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_021(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("qualifying_prices", facts.get("qualifying_prices") is True)
        context.check("minimum_set", facts.get("minimum_set") is True)
        context.check("chosen_offer", facts.get("chosen_offer") is True)
        context.check("verified_delivery", facts.get("verified_delivery") is True)
        context.check("expense", facts.get("expense") is True)
        context.check("exact_credit", facts.get("exact_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_022(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_022(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("qualifying_prices", facts.get("qualifying_prices") is True)
        context.check("minimum_set", facts.get("minimum_set") is True)
        context.check("chosen_offer", facts.get("chosen_offer") is True)
        context.check("verified_delivery", facts.get("verified_delivery") is True)
        context.check("expense", facts.get("expense") is True)
        context.check("exact_credit", facts.get("exact_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_023(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_023(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("input_principal", facts.get("input_principal") is True)
        context.check("route_receipts", facts.get("route_receipts") is True)
        context.check("native_output", facts.get("native_output") is True)
        context.check("weth_balance", facts.get("weth_balance") is True)
        context.check("reserve", facts.get("reserve") is True)
        context.check("expense", facts.get("expense") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_024(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_024(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("input_principal", facts.get("input_principal") is True)
        context.check("route_receipts", facts.get("route_receipts") is True)
        context.check("native_output", facts.get("native_output") is True)
        context.check("weth_balance", facts.get("weth_balance") is True)
        context.check("reserve", facts.get("reserve") is True)
        context.check("expense", facts.get("expense") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_025(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_025(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("exchange_predicate", facts.get("exchange_predicate") is True)
        context.check("used_spenders", facts.get("used_spenders") is True)
        context.check("final_allowances", facts.get("final_allowances") is True)
        context.check("unrelated_history", facts.get("unrelated_history") is True)
        context.check("exact_credit", facts.get("exact_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_026(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_026(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("exchange_predicate", facts.get("exchange_predicate") is True)
        context.check("used_spenders", facts.get("used_spenders") is True)
        context.check("final_allowances", facts.get("final_allowances") is True)
        context.check("unrelated_history", facts.get("unrelated_history") is True)
        context.check("exact_credit", facts.get("exact_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_027(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_027(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("component_validators", facts.get("component_validators") is True)
        context.check("delivered_component_set", facts.get("delivered_component_set") is True)
        context.check("payment_identities", facts.get("payment_identities") is True)
        context.check("expense", facts.get("expense") is True)
        context.check("component_fraction", facts.get("component_fraction") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_028(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_028(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("component_validators", facts.get("component_validators") is True)
        context.check("delivered_component_set", facts.get("delivered_component_set") is True)
        context.check("payment_identities", facts.get("payment_identities") is True)
        context.check("expense", facts.get("expense") is True)
        context.check("component_fraction", facts.get("component_fraction") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_029(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_029(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("obligation_results", facts.get("obligation_results") is True)
        context.check("recipient_deltas", facts.get("recipient_deltas") is True)
        context.check("conversion_receipts", facts.get("conversion_receipts") is True)
        context.check("native_reserve", facts.get("native_reserve") is True)
        context.check("expense", facts.get("expense") is True)
        context.check("payout_fraction", facts.get("payout_fraction") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_030(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_030(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("obligation_results", facts.get("obligation_results") is True)
        context.check("recipient_deltas", facts.get("recipient_deltas") is True)
        context.check("conversion_receipts", facts.get("conversion_receipts") is True)
        context.check("native_reserve", facts.get("native_reserve") is True)
        context.check("expense", facts.get("expense") is True)
        context.check("payout_fraction", facts.get("payout_fraction") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_031(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_031(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("paid_reference", facts.get("paid_reference") is True)
        context.check("delivery_sequence", facts.get("delivery_sequence") is True)
        context.check("trade_sequence", facts.get("trade_sequence") is True)
        context.check("derived_route_objective", facts.get("derived_route_objective") is True)
        context.check("actual_outcome", facts.get("actual_outcome") is True)
        context.check("combined_expense", facts.get("combined_expense") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_032(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_032(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("paid_reference", facts.get("paid_reference") is True)
        context.check("delivery_sequence", facts.get("delivery_sequence") is True)
        context.check("trade_sequence", facts.get("trade_sequence") is True)
        context.check("derived_route_objective", facts.get("derived_route_objective") is True)
        context.check("actual_outcome", facts.get("actual_outcome") is True)
        context.check("combined_expense", facts.get("combined_expense") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_033(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_033(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("release_pinned_data_denominator", facts.get("release_pinned_data_denominator") is True)
        context.check("release_pinned_payout_denominator", facts.get("release_pinned_payout_denominator") is True)
        context.check("validated_component_ids", facts.get("validated_component_ids") is True)
        context.check("component_validator_results", facts.get("component_validator_results") is True)
        context.check("component_delivery_hashes", facts.get("component_delivery_hashes") is True)
        context.check("fulfilled_obligation_ids", facts.get("fulfilled_obligation_ids") is True)
        context.check("payout_recipient_deltas", facts.get("payout_recipient_deltas") is True)
        context.check("payout_receipt_ids", facts.get("payout_receipt_ids") is True)
        context.check("allocation_asset_set", facts.get("allocation_asset_set") is True)
        context.check("post_payout_asset_values", facts.get("post_payout_asset_values") is True)
        context.check("allocation_target_tolerance", facts.get("allocation_target_tolerance") is True)
        context.check("temporary_allowance_keys", facts.get("temporary_allowance_keys") is True)
        context.check("data_fraction", facts.get("data_fraction") is True)
        context.check("post_payout_allocation", facts.get("post_payout_allocation") is True)
        context.check("payout_fraction", facts.get("payout_fraction") is True)
        context.check("temporary_allowances", facts.get("temporary_allowances") is True)
        context.check("core_progress_guard", facts.get("core_progress_guard") is True)
        context.check("common_cutoff", facts.get("common_cutoff") is True)
        context.check("weighted_credit", facts.get("weighted_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

    def _execute_BTS_SC_034(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _verify_BTS_SC_034(self, context: ScenarioContext) -> None:
        facts = self._verify_evidence(context)
        context.check("release_pinned_data_denominator", facts.get("release_pinned_data_denominator") is True)
        context.check("release_pinned_payout_denominator", facts.get("release_pinned_payout_denominator") is True)
        context.check("validated_component_ids", facts.get("validated_component_ids") is True)
        context.check("component_validator_results", facts.get("component_validator_results") is True)
        context.check("component_delivery_hashes", facts.get("component_delivery_hashes") is True)
        context.check("fulfilled_obligation_ids", facts.get("fulfilled_obligation_ids") is True)
        context.check("payout_recipient_deltas", facts.get("payout_recipient_deltas") is True)
        context.check("payout_receipt_ids", facts.get("payout_receipt_ids") is True)
        context.check("allocation_asset_set", facts.get("allocation_asset_set") is True)
        context.check("post_payout_asset_values", facts.get("post_payout_asset_values") is True)
        context.check("allocation_target_tolerance", facts.get("allocation_target_tolerance") is True)
        context.check("temporary_allowance_keys", facts.get("temporary_allowance_keys") is True)
        context.check("data_fraction", facts.get("data_fraction") is True)
        context.check("post_payout_allocation", facts.get("post_payout_allocation") is True)
        context.check("payout_fraction", facts.get("payout_fraction") is True)
        context.check("temporary_allowances", facts.get("temporary_allowances") is True)
        context.check("core_progress_guard", facts.get("core_progress_guard") is True)
        context.check("common_cutoff", facts.get("common_cutoff") is True)
        context.check("weighted_credit", facts.get("weighted_credit") is True)
        context.check("case_hash", facts.get("case_hash") is True)
        context.check("cutoff", facts.get("cutoff") is True)
        context.check("raw_paths_hashes", facts.get("raw_paths_hashes") is True)

def register(registry: ScenarioRegistry) -> None:
    proposal, contract, _ = _load_contract_sources()
    for scenario_id in SCENARIO_IDS:
        registry.register(
            scenario_id,
            BenchmarkTaskSuiteEvidenceCase(scenario_id, proposal["protected_scenarios"][scenario_id], contract["protected_scenarios"][scenario_id]),
            adapter_profile=proposal["protected_scenarios"][scenario_id]["adapter"],
        )
