"""Machine-readable semantic contracts for the Web3 Agent Bench BDD harness."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


MANIFEST_RELATIVE = Path("tests") / "bdd" / "harness-contracts.json"
MAIN_SPECS_RELATIVE = Path("openspec") / "specs"
CHANGE_ROOT_RELATIVE = Path("openspec") / "changes"
ACTIVE_RUNTIME_ROOT = Path("tests") / "bdd" / "changes"
_CHANGE_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# AICODE-NOTE: Boundary names are deliberately explicit. A local reference model must not be
# silently reported as a sandbox, chain, match-server, or settlement result.
ALLOWED_BOUNDARIES = frozenset(
    {
        "reference_model",
        "sandbox",
        "chain_observation",
        "match_authority",
        "settlement",
        "domain_adversarial",
        "process",
        "artifact",
        "environment",
    }
)
_REQUIREMENT_RE = re.compile(r"^### Requirement: (?P<id>[A-Z]+-REQ-\d+) ", re.MULTILINE)
_NORMATIVE_WORD_RE = re.compile(r"\b(?:MUST|SHALL)\b", re.IGNORECASE)


@dataclass(frozen=True)
class HarnessContract:
    """Reviewed semantic obligations for one protected scenario."""

    scenario_id: str
    boundary: str
    required_observations: tuple[str, ...]
    negative_variants: tuple[str, ...]
    durable_effects: tuple[str, ...]
    evidence_mode: str
    allowed_private_calls: tuple[str, ...]


def validate_change_name(change_name: str) -> str:
    """Reject names that could escape the repository's change-owned paths."""

    if not isinstance(change_name, str) or not _CHANGE_NAME_RE.fullmatch(change_name):
        raise ValueError(f"invalid OpenSpec change name: {change_name!r}")
    return change_name


def change_root(root: Path, change_name: str) -> Path:
    return root / CHANGE_ROOT_RELATIVE / validate_change_name(change_name)


def change_spec_paths(root: Path, change_name: str) -> tuple[Path, ...]:
    """Return the active delta's normative spec paths relative to the repository."""

    directory = change_root(root, change_name) / "specs"
    return tuple(
        sorted(
            (path.relative_to(root) for path in directory.glob("*/spec.md")),
            key=lambda item: item.as_posix(),
        )
    )


def proposal_path(root: Path, change_name: str) -> Path:
    return change_root(root, change_name) / "bdd-harness-proposal.json"


def manifest_path(root: Path, change_name: str | None = None) -> Path:
    if change_name is None:
        return root / MANIFEST_RELATIVE
    return root / ACTIVE_RUNTIME_ROOT / validate_change_name(change_name) / "harness-contracts.json"


def acceptance_path(root: Path, change_name: str | None = None) -> Path:
    if change_name is None:
        return root / "tests" / "bdd" / "acceptance-evidence.json"
    return root / ACTIVE_RUNTIME_ROOT / validate_change_name(change_name) / "acceptance-evidence.json"


def scenario_map_path(root: Path, change_name: str | None = None) -> Path:
    if change_name is None:
        return root / "tests" / "bdd" / "scenario-map.md"
    return root / ACTIVE_RUNTIME_ROOT / validate_change_name(change_name) / "scenario-map.md"


def load_proposal(root: Path, change_name: str) -> dict[str, Any]:
    """Load an approved review inventory; this is never a runtime contract."""

    path = proposal_path(root, change_name)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load active BDD proposal {path}: {error}") from error
    if not isinstance(payload, dict) or payload.get("proposal_schema") != "bdd-harness-contract-proposal/v1":
        raise ValueError("active BDD proposal must use bdd-harness-contract-proposal/v1")
    if payload.get("review_status") != "approved":
        raise ValueError(
            f"active BDD proposal {change_name!r} is not approved; "
            f"review_status={payload.get('review_status')!r}"
        )
    normative_delta = payload.get("normative_delta")
    if not isinstance(normative_delta, str) or not normative_delta.strip():
        raise ValueError("active BDD proposal must declare normative_delta")
    normative_path = Path(normative_delta)
    selected_specs = {
        (root / path).relative_to(change_root(root, change_name)).as_posix()
        for path in change_spec_paths(root, change_name)
    }
    if (
        normative_path.is_absolute()
        or ".." in normative_path.parts
        or normative_path.as_posix() not in selected_specs
    ):
        raise ValueError(f"active BDD proposal targets unexpected normative delta {normative_delta!r}")
    expected_manifest = manifest_path(root, change_name).relative_to(root).as_posix()
    if payload.get("runtime_manifest") != expected_manifest:
        raise ValueError(
            "active BDD proposal runtime_manifest does not target its separate runtime contract: "
            f"expected {expected_manifest!r}, found {payload.get('runtime_manifest')!r}"
        )
    scenarios = payload.get("protected_scenarios")
    if not isinstance(scenarios, dict) or not scenarios:
        raise ValueError("active BDD proposal must declare protected_scenarios")
    for scenario_id, row in scenarios.items():
        if not isinstance(scenario_id, str) or not scenario_id.strip() or not isinstance(row, dict):
            raise ValueError("active BDD proposal has an invalid protected_scenarios entry")
        required_text = ("requirement_id", "title", "named_mapper", "adapter", "boundary", "evidence_mode")
        for field in required_text:
            value = row.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"proposal scenario {scenario_id} needs non-empty {field}")
        if row.get("mandatory") is not True:
            raise ValueError(f"proposal scenario {scenario_id} must be mandatory")
        if not isinstance(row.get("gate"), str) or not row["gate"].strip():
            raise ValueError(f"proposal scenario {scenario_id} needs a gate")
        for field in ("required_observations", "negative_variants", "durable_effects"):
            values = row.get(field)
            if not isinstance(values, list) or not values or not all(
                isinstance(item, str) and item.strip() for item in values
            ):
                raise ValueError(f"proposal scenario {scenario_id} needs non-empty {field}")
            if len(set(values)) != len(values):
                raise ValueError(f"proposal scenario {scenario_id} has duplicate {field}")
        allowed_private_calls = row.get("allowed_private_calls", [])
        if not isinstance(allowed_private_calls, list) or not all(
            isinstance(item, str) and item.strip() for item in allowed_private_calls
        ):
            raise ValueError(f"proposal scenario {scenario_id} has invalid allowed_private_calls")
    return payload


def validate_proposal_inventory(
    proposal: dict[str, Any], scenarios: Iterable[Any], contracts: dict[str, "HarnessContract"] | None = None
) -> None:
    """Bind the approved proposal to source scenarios and, when present, runtime contracts."""

    scenario_list = list(scenarios)
    planned = proposal["protected_scenarios"]
    expected_ids = {scenario.scenario_id for scenario in scenario_list}
    planned_ids = set(planned)
    if planned_ids != expected_ids:
        raise ValueError(
            "active BDD proposal scenario inventory drifted: "
            f"missing={sorted(expected_ids - planned_ids)}, extra={sorted(planned_ids - expected_ids)}"
        )
    for scenario in scenario_list:
        row = planned[scenario.scenario_id]
        comparisons = {
            "requirement_id": scenario.requirement_id,
            "title": scenario.title,
            "named_mapper": scenario.mapper_name,
        }
        for field, expected in comparisons.items():
            if row[field] != expected:
                raise ValueError(
                    f"active BDD proposal drift for {scenario.scenario_id} {field}: "
                    f"expected {expected!r}, found {row[field]!r}"
                )
    if contracts is None:
        return
    contract_ids = set(contracts)
    if contract_ids != expected_ids:
        raise ValueError(
            "active runtime contract inventory drifted: "
            f"missing={sorted(expected_ids - contract_ids)}, extra={sorted(contract_ids - expected_ids)}"
        )
    contract_fields = {
        "boundary": "boundary",
        "required_observations": "required_observations",
        "negative_variants": "negative_variants",
        "durable_effects": "durable_effects",
        "evidence_mode": "evidence_mode",
        "allowed_private_calls": "allowed_private_calls",
    }
    for scenario_id, contract in contracts.items():
        row = planned[scenario_id]
        for proposal_field, contract_field in contract_fields.items():
            if tuple(row[proposal_field]) != tuple(getattr(contract, contract_field)):
                raise ValueError(
                    f"active runtime contract drift for {scenario_id} {proposal_field}"
                )


def load_manifest(
    root: Path, change_name: str | None = None
) -> tuple[dict[str, Any], dict[str, HarnessContract]]:
    """Load and structurally validate the selected runtime semantic contract."""

    path = manifest_path(root, change_name)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        if change_name is not None and not path.exists():
            raise ValueError(
                f"active change {change_name!r} has no runtime harness contract at {path}; "
                "the approved proposal inventory is not a runtime contract"
            ) from error
        raise ValueError(f"cannot load harness contract {path}: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("harness contract must be an object with schema_version=1")

    snapshot = payload.get("spec_snapshot")
    if not isinstance(snapshot, dict):
        raise ValueError("harness contract has no spec_snapshot object")
    required_snapshot_keys = (
        "requirements",
        "scenarios",
        "normative_clauses",
        "requirement_clause_counts",
        "scenario_requirement_sha256",
        "scenario_ids_sha256",
        "scenario_requirement_mapping",
    )
    for key in required_snapshot_keys:
        if key not in snapshot:
            raise ValueError(f"harness contract spec_snapshot is missing {key!r}")

    coverage_policy = payload.get("coverage_policy")
    if not isinstance(coverage_policy, dict):
        raise ValueError("harness contract must declare coverage_policy")
    if coverage_policy.get("status") not in {"partial", "complete"}:
        raise ValueError("coverage_policy.status must be partial or complete")
    required_protected = coverage_policy.get("required_protected_scenarios")
    if not isinstance(required_protected, list) or not all(
        isinstance(item, str) and item.strip() for item in required_protected
    ):
        raise ValueError("coverage_policy.required_protected_scenarios must be a list of IDs")
    if len(set(required_protected)) != len(required_protected):
        raise ValueError("coverage_policy.required_protected_scenarios has duplicates")

    raw_contracts = payload.get("protected_scenarios")
    if not isinstance(raw_contracts, dict) or not raw_contracts:
        raise ValueError("harness contract must declare protected_scenarios")

    contracts: dict[str, HarnessContract] = {}
    for scenario_id, raw in raw_contracts.items():
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("protected scenario IDs must be non-empty strings")
        if not isinstance(raw, dict):
            raise ValueError(f"contract for {scenario_id} must be an object")
        boundary = raw.get("boundary")
        if boundary not in ALLOWED_BOUNDARIES:
            raise ValueError(f"contract for {scenario_id} has unsupported boundary {boundary!r}")

        fields: dict[str, tuple[str, ...]] = {}
        for field in ("required_observations", "negative_variants", "durable_effects"):
            value = raw.get(field)
            if not isinstance(value, list) or not value or not all(
                isinstance(item, str) and item.strip() for item in value
            ):
                raise ValueError(f"contract for {scenario_id} needs non-empty {field}")
            if len(set(value)) != len(value):
                raise ValueError(f"contract for {scenario_id} has duplicate {field}")
            fields[field] = tuple(value)

        allowed_private_calls = raw.get("allowed_private_calls", [])
        if not isinstance(allowed_private_calls, list) or not all(
            isinstance(item, str) and item.strip() for item in allowed_private_calls
        ):
            raise ValueError(f"contract for {scenario_id} has invalid allowed_private_calls")
        if len(set(allowed_private_calls)) != len(allowed_private_calls):
            raise ValueError(f"contract for {scenario_id} has duplicate allowed_private_calls")

        evidence_mode = raw.get("evidence_mode")
        if not isinstance(evidence_mode, str) or not evidence_mode.strip():
            raise ValueError(f"contract for {scenario_id} needs evidence_mode")
        contracts[scenario_id] = HarnessContract(
            scenario_id=scenario_id,
            boundary=boundary,
            required_observations=fields["required_observations"],
            negative_variants=fields["negative_variants"],
            durable_effects=fields["durable_effects"],
            evidence_mode=evidence_mode,
            allowed_private_calls=tuple(allowed_private_calls),
        )
    return payload, contracts


def scenario_requirement_digest(scenarios: Iterable[Any]) -> str:
    pairs = sorted(f"{item.requirement_id}:{item.scenario_id}" for item in scenarios)
    return hashlib.sha256(("\n".join(pairs) + "\n").encode("utf-8")).hexdigest()


def scenario_id_digest(scenarios: Iterable[Any]) -> str:
    scenario_ids = sorted(item.scenario_id for item in scenarios)
    return hashlib.sha256(("\n".join(scenario_ids) + "\n").encode("utf-8")).hexdigest()


def source_spec_paths(root: Path, change_name: str | None = None) -> tuple[Path, ...]:
    """Return selected normative spec paths; no change selects synchronized main specs."""

    if change_name is None:
        return main_spec_paths(root)
    return change_spec_paths(root, change_name)


def requirement_clause_counts(root: Path, change_name: str | None = None) -> dict[str, int]:
    """Count normative clauses in the selected source for drift detection."""

    counts: dict[str, int] = {}
    paths = source_spec_paths(root, change_name)
    if not paths:
        selected = "main specs" if change_name is None else f"change {change_name!r} specs"
        raise ValueError(f"no normative spec files found for {selected}")
    for relative in paths:
        source = root / relative
        text = source.read_text(encoding="utf-8")
        matches = list(_REQUIREMENT_RE.finditer(text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            requirement_id = match.group("id")
            if requirement_id in counts:
                raise ValueError(f"duplicate requirement ID in selected specs: {requirement_id}")
            counts[requirement_id] = len(_NORMATIVE_WORD_RE.findall(text[match.end() : end]))
    return dict(sorted(counts.items()))


def current_spec_snapshot(
    root: Path, scenarios: Iterable[Any], change_name: str | None = None
) -> dict[str, Any]:
    scenario_list = list(scenarios)
    clause_counts = requirement_clause_counts(root, change_name)
    scenario_mapping = dict(
        sorted((item.scenario_id, item.requirement_id) for item in scenario_list)
    )
    return {
        "requirements": len(clause_counts),
        "scenarios": len(scenario_list),
        "normative_clauses": sum(clause_counts.values()),
        "requirement_clause_counts": clause_counts,
        "scenario_requirement_sha256": scenario_requirement_digest(scenario_list),
        "scenario_ids_sha256": scenario_id_digest(scenario_list),
        "scenario_requirement_mapping": scenario_mapping,
    }


def validate_spec_snapshot(
    root: Path,
    scenarios: Iterable[Any],
    payload: dict[str, Any],
    change_name: str | None = None,
) -> None:
    expected = current_spec_snapshot(root, scenarios, change_name)
    actual = payload.get("spec_snapshot")
    if actual != expected:
        raise ValueError(
            "harness contract spec snapshot is stale; "
            f"expected {json.dumps(expected, sort_keys=True)}, "
            f"found {json.dumps(actual, sort_keys=True)}"
        )


def sha256_files(root: Path, relative_paths: Iterable[Path]) -> str:
    """Hash relative names and bytes so evidence identifies its inputs."""

    digest = hashlib.sha256()
    for relative in sorted(relative_paths, key=lambda item: item.as_posix()):
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update((root / relative).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main_spec_paths(root: Path) -> tuple[Path, ...]:
    return tuple(
        sorted(
            (path.relative_to(root) for path in (root / MAIN_SPECS_RELATIVE).glob("*/spec.md")),
            key=lambda item: item.as_posix(),
        )
    )


def active_delta_source_paths(root: Path, change_name: str) -> tuple[Path, ...]:
    """Return active approval, design, spec, proposal, and runtime-contract inputs."""

    name = validate_change_name(change_name)
    paths = set(change_spec_paths(root, name))
    selected_change_root = change_root(root, name)
    for filename in (
        "approval.md",
        "proposal.md",
        "design.md",
        "bdd-design.md",
        "bdd-harness-proposal.json",
        "tasks.md",
    ):
        candidate = selected_change_root / filename
        if candidate.is_file():
            paths.add(candidate.relative_to(root))
    selected_manifest = manifest_path(root, name)
    if selected_manifest.is_file():
        paths.add(selected_manifest.relative_to(root))
    return tuple(sorted(paths, key=lambda item: item.as_posix()))


def harness_source_paths(root: Path, change_name: str | None = None) -> tuple[Path, ...]:
    """Return executable/normative inputs, excluding result-bearing scenario maps."""

    paths: set[Path] = set()
    for relative in (
        Path("tools") / "check_bdd_harness.py",
        Path("tools") / "replay_bef_evidence.py",
        Path("tools") / "run_bef_sc011_trials.py",
        Path("tools") / "bef_resource_sampler.py",
        Path("tools") / "generate_bdd_mirrors.py",
        Path("tools") / "harness_contracts.py",
        Path("tools") / "run_bdd_acceptance.py",
        Path("tests") / "bdd" / "conftest.py",
    ):
        if (root / relative).is_file():
            paths.add(relative)
    for directory, patterns in (
        (Path("tests") / "bdd" / "adapters", ("*.py",)),
        (Path("tests") / "bdd" / "features", ("*.feature",)),
        (Path("tests") / "bdd" / "mappers", ("test_*_bdd.py",)),
        (Path("tests") / "bdd" / "traceability", ("*.py",)),
    ):
        for pattern in patterns:
            paths.update(
                path.relative_to(root)
                for path in (root / directory).glob(pattern)
                if path.is_file()
            )
    paths.update(main_spec_paths(root))
    selected_manifest = manifest_path(root, change_name)
    if selected_manifest.is_file():
        paths.add(selected_manifest.relative_to(root))
    if change_name is not None:
        paths.update(active_delta_source_paths(root, change_name))
    return tuple(sorted(paths, key=lambda item: item.as_posix()))

