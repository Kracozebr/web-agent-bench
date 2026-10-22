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


def manifest_path(root: Path) -> Path:
    return root / MANIFEST_RELATIVE


def load_manifest(root: Path) -> tuple[dict[str, Any], dict[str, HarnessContract]]:
    """Load and structurally validate the checked-in semantic contract."""

    path = manifest_path(root)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
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


def requirement_clause_counts(root: Path) -> dict[str, int]:
    """Count normative MUST/SHALL clauses per main requirement for drift detection."""

    counts: dict[str, int] = {}
    for source in sorted((root / MAIN_SPECS_RELATIVE).glob("*/spec.md")):
        text = source.read_text(encoding="utf-8")
        matches = list(_REQUIREMENT_RE.finditer(text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            requirement_id = match.group("id")
            if requirement_id in counts:
                raise ValueError(f"duplicate requirement ID in main specs: {requirement_id}")
            counts[requirement_id] = len(_NORMATIVE_WORD_RE.findall(text[match.end() : end]))
    return dict(sorted(counts.items()))


def current_spec_snapshot(root: Path, scenarios: Iterable[Any]) -> dict[str, Any]:
    scenario_list = list(scenarios)
    clause_counts = requirement_clause_counts(root)
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


def validate_spec_snapshot(root: Path, scenarios: Iterable[Any], payload: dict[str, Any]) -> None:
    expected = current_spec_snapshot(root, scenarios)
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


def harness_source_paths(root: Path) -> tuple[Path, ...]:
    """Return the tracked source set whose behavior the acceptance gate exercises."""

    paths: set[Path] = set()
    for relative in (
        Path("tools") / "check_bdd_harness.py",
        Path("tools") / "generate_bdd_mirrors.py",
        Path("tools") / "harness_contracts.py",
        Path("tools") / "run_bdd_acceptance.py",
        Path("tests") / "bdd" / "conftest.py",
        Path("tests") / "bdd" / "scenario-map.md",
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
    return tuple(sorted(paths, key=lambda item: item.as_posix()))

