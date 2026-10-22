#!/usr/bin/env python3
"""Generate and validate BDD mirrors against synchronized OpenSpec main specs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.harness_contracts import load_manifest, validate_spec_snapshot


CHANGE_NAME = "web3-agent-bench-baseline"
MAIN_SPECS_RELATIVE = Path("openspec") / "specs"
LIFECYCLE_PHASE = "synced-main"
NORMATIVE_SOURCE = "openspec/specs/*/spec.md"
EXPECTED_EVIDENCE = "Named observations from the declared adapter boundary"
ACCEPTANCE_RELATIVE = Path("tests") / "bdd" / "acceptance-evidence.json"

REQUIREMENT_RE = re.compile(r"^### Requirement: (?P<id>[A-Z]+-REQ-\d+) (?P<title>.+)$")
SCENARIO_RE = re.compile(r"^#### Scenario: (?P<id>[A-Z]+-SC-\d+) (?P<title>.+)$")
WHEN_RE = re.compile(r"^- \*\*WHEN\*\* (?P<text>.+)$")
THEN_RE = re.compile(r"^- \*\*THEN\*\* (?P<text>.+)$")


@dataclass(frozen=True)
class Capability:
    directory: str
    slug: str
    label: str
    adapter: str


@dataclass(frozen=True)
class Scenario:
    capability: Capability
    requirement_id: str
    scenario_id: str
    title: str
    when: str
    then: str
    source_relative_path: Path

    @property
    def feature_tag(self) -> str:
        return f"@scn_{self.scenario_id.lower().replace('-', '_')}"

    @property
    def requirement_tag(self) -> str:
        return f"@req_{self.requirement_id.lower().replace('-', '_')}"

    @property
    def mapper_name(self) -> str:
        return f"test_{self.scenario_id.lower().replace('-', '_')}"


class ContractError(ValueError):
    """The approved specification, contract, or generated mirror has drifted."""


def _capabilities(root: Path) -> tuple[Capability, ...]:
    capabilities: list[Capability] = []
    for spec_path in sorted((root / MAIN_SPECS_RELATIVE).glob("*/spec.md")):
        label = spec_path.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ").strip()
        directory = spec_path.parent.name
        capabilities.append(
            Capability(
                directory=directory,
                slug=directory.replace("-", "_"),
                label=label,
                adapter=directory.replace("-", "_") + "_adapter",
            )
        )
    if not capabilities:
        raise ContractError(f"no main OpenSpec specs found under {MAIN_SPECS_RELATIVE}")
    return tuple(capabilities)


def _parse_spec_source(
    root: Path,
    capability: Capability,
    scenarios: list[Scenario],
    seen_ids: set[str],
) -> None:
    source_relative = MAIN_SPECS_RELATIVE / capability.directory / "spec.md"
    source = root / source_relative
    lines = source.read_text(encoding="utf-8").splitlines()
    current_requirement: str | None = None
    index = 0
    while index < len(lines):
        line = lines[index]
        requirement_match = REQUIREMENT_RE.match(line)
        if requirement_match:
            current_requirement = requirement_match.group("id")
            index += 1
            continue
        scenario_match = SCENARIO_RE.match(line)
        if not scenario_match:
            index += 1
            continue
        if current_requirement is None:
            raise ContractError(f"{source}: scenario appears before a requirement: {line}")
        if index + 2 >= len(lines):
            raise ContractError(f"{source}: incomplete WHEN/THEN for {scenario_match.group('id')}")
        when_match = WHEN_RE.match(lines[index + 1])
        then_match = THEN_RE.match(lines[index + 2])
        if not when_match or not then_match:
            raise ContractError(
                f"{source}: {scenario_match.group('id')} must have adjacent exact WHEN/THEN lines"
            )
        scenario_id = scenario_match.group("id")
        if scenario_id in seen_ids:
            raise ContractError(f"duplicate approved scenario ID: {scenario_id}")
        seen_ids.add(scenario_id)
        scenarios.append(
            Scenario(
                capability=capability,
                requirement_id=current_requirement,
                scenario_id=scenario_id,
                title=scenario_match.group("title"),
                when=when_match.group("text"),
                then=then_match.group("text"),
                source_relative_path=source_relative,
            )
        )
        index += 3


def parse_specs(root: Path) -> list[Scenario]:
    """Parse the complete synchronized main-spec scenario inventory."""

    scenarios: list[Scenario] = []
    seen_ids: set[str] = set()
    for capability in _capabilities(root):
        _parse_spec_source(root, capability, scenarios, seen_ids)
    if not scenarios:
        raise ContractError("main specs contain no scenarios")
    return scenarios


def render_feature(capability: Capability, scenarios: Iterable[Scenario]) -> str:
    scenarios = list(scenarios)
    sources = sorted({scenario.source_relative_path.as_posix() for scenario in scenarios})
    lines = [
        "# Generated by tools/generate_bdd_mirrors.py; DO NOT EDIT.",
        f"# Normative source(s): {', '.join(sources)}",
        "# Scenario tags use underscores solely because pytest markers cannot safely use hyphens.",
        "",
        f"@cap_{capability.slug}",
        f"Feature: {capability.label} approved scenarios",
        "  Executable mirror of the synchronized main OpenSpec contract.",
    ]
    for scenario in scenarios:
        lines.extend(
            [
                "",
                f"  {scenario.requirement_tag} {scenario.feature_tag} @gate_local @mandatory",
                f"  Scenario: {scenario.title}",
                f'    Given the approved local setup for "{scenario.scenario_id}"',
                f"    When {scenario.when}",
                f"    Then {scenario.then}",
            ]
        )
    return "\n".join(lines) + "\n"


def render_mapper(capability: Capability, scenarios: Iterable[Scenario]) -> str:
    scenarios = list(scenarios)
    sources = sorted({scenario.source_relative_path.as_posix() for scenario in scenarios})
    feature = f"../features/{capability.slug}.feature"
    lines = [
        "# Generated by tools/generate_bdd_mirrors.py; DO NOT EDIT.",
        f"# Normative source(s): {', '.join(sources)}",
        "",
        "from pytest_bdd import scenario",
    ]
    for approved_scenario in scenarios:
        lines.extend(
            [
                "",
                f'@scenario("{feature}", "{approved_scenario.title}")',
                f"def {approved_scenario.mapper_name}():",
                f'    """Named mapper for {approved_scenario.scenario_id}."""',
            ]
        )
    return "\n".join(lines) + "\n"


def load_acceptance_results(
    root: Path, scenarios: Iterable[Scenario], evidence_path: Path | None = None
) -> dict[str, str]:
    """Load a durable local-gate record, failing closed on stale inventory."""

    scenarios = list(scenarios)
    evidence_path = evidence_path or root / ACCEPTANCE_RELATIVE
    if not evidence_path.exists():
        return {scenario.scenario_id: "not_run" for scenario in scenarios}
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read acceptance evidence: {error}") from error
    if payload.get("change") != CHANGE_NAME:
        return {scenario.scenario_id: "not_run" for scenario in scenarios}
    if payload.get("acceptance_state") == "running":
        return {scenario.scenario_id: "not_run" for scenario in scenarios}
    if payload.get("acceptance_state") not in {"complete", "failed"}:
        return {scenario.scenario_id: "not_run" for scenario in scenarios}
    if payload.get("lifecycle_phase") != LIFECYCLE_PHASE or payload.get("normative_source") != NORMATIVE_SOURCE:
        raise ContractError("BDD acceptance evidence does not target synchronized main specs")
    results = payload.get("scenario_results")
    expected_ids = {scenario.scenario_id for scenario in scenarios}
    if not isinstance(results, dict) or set(results) != expected_ids:
        raise ContractError("BDD acceptance evidence scenario inventory drifted")
    allowed_results = {"not_run", "passed", "failed", "skipped", "blocked"}
    if any(result not in allowed_results for result in results.values()):
        raise ContractError("BDD acceptance evidence contains an invalid result")
    return {str(scenario_id): str(result) for scenario_id, result in results.items()}


def render_scenario_map(
    scenarios: Iterable[Scenario], results: dict[str, str], contracts: dict[str, object]
) -> str:
    lines = [
        f"# Scenario map: `{CHANGE_NAME}`",
        "",
        "Workflow: [`docs/task-design.md`](../../docs/task-design.md)",
        "",
        f"**Lifecycle phase:** `{LIFECYCLE_PHASE}`",
        f"**Normative source:** `{NORMATIVE_SOURCE}`",
        "**Acceptance evidence:** `tests/bdd/acceptance-evidence.json`",
        "",
        "| Requirement ID | Scenario ID | Mirrored title | Feature tag | Named mapper | Adapter | Gate | Mandatory | Harness contract | Evidence | Result |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for scenario in scenarios:
        contract = contracts.get(scenario.scenario_id)
        if contract is None:
            contract_summary = "unprotected; see harness audit"
            evidence = EXPECTED_EVIDENCE
        else:
            contract_summary = (
                f"`{contract.boundary}`; observations: {', '.join(contract.required_observations)}; "
                f"negatives: {', '.join(contract.negative_variants)}; effects: "
                f"{', '.join(contract.durable_effects)}; evidence: {contract.evidence_mode}"
            )
            evidence = contract.evidence_mode
        lines.append(
            "| "
            f"`{scenario.requirement_id}` | `{scenario.scenario_id}` | {scenario.title} | "
            f"`{scenario.feature_tag}` | `{scenario.mapper_name}` | `{scenario.capability.adapter}` | "
            f"`local` | yes | {contract_summary} | {evidence} | `{results[scenario.scenario_id]}` |"
        )
    lines.extend(
        [
            "",
            "## Source transition",
            "",
            "- [x] Normative behavior resolves to synchronized main capability specs.",
            "- [x] OpenSpec scenario IDs and titles equal the Gherkin and named-mapper inventories.",
            "- [x] No executable reference targets an active change path in this baseline.",
        ]
    )
    return "\n".join(lines) + "\n"


def expected_outputs(
    root: Path, scenarios: list[Scenario], acceptance_evidence_path: Path | None = None
) -> dict[Path, str]:
    manifest, contracts = load_manifest(root)
    validate_spec_snapshot(root, scenarios, manifest)
    results = load_acceptance_results(root, scenarios, acceptance_evidence_path)
    outputs: dict[Path, str] = {
        root / "tests" / "bdd" / "scenario-map.md": render_scenario_map(
            scenarios, results, contracts
        )
    }
    for capability in _capabilities(root):
        capability_scenarios = [scenario for scenario in scenarios if scenario.capability == capability]
        outputs[root / "tests" / "bdd" / "features" / f"{capability.slug}.feature"] = render_feature(
            capability, capability_scenarios
        )
        outputs[root / "tests" / "bdd" / "mappers" / f"test_{capability.slug}_bdd.py"] = render_mapper(
            capability, capability_scenarios
        )
    return outputs


def validate_generated_inventory(root: Path, outputs: dict[Path, str]) -> list[Path]:
    stale = [
        path
        for path, expected in outputs.items()
        if not path.is_file() or path.read_text(encoding="utf-8") != expected
    ]
    features = root / "tests" / "bdd" / "features"
    mappers = root / "tests" / "bdd" / "mappers"
    expected_feature_paths = {path for path in outputs if path.parent == features}
    expected_mapper_paths = {path for path in outputs if path.parent == mappers}
    actual_feature_paths = set(features.glob("*.feature")) if features.exists() else set()
    actual_mapper_paths = set(mappers.glob("test_*_bdd.py")) if mappers.exists() else set()
    unexpected = sorted(
        (actual_feature_paths - expected_feature_paths)
        | (actual_mapper_paths - expected_mapper_paths),
        key=lambda path: path.as_posix(),
    )
    return stale + unexpected


def generate(root: Path, check: bool, acceptance_evidence_path: Path | None = None) -> int:
    scenarios = parse_specs(root)
    outputs = expected_outputs(root, scenarios, acceptance_evidence_path)
    stale = validate_generated_inventory(root, outputs)
    if check:
        if stale:
            print("BDD mirror validation failed; regenerate or remove stale generated paths:", file=sys.stderr)
            for path in stale:
                print(f"- {path.relative_to(root).as_posix()}", file=sys.stderr)
            return 1
        print(f"BDD mirror validation passed: {len(scenarios)} approved scenarios.")
        return 0
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    print(f"Generated BDD mirrors: {len(scenarios)} approved scenarios across {len(_capabilities(root))} capabilities.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail instead of writing stale mirrors")
    parser.add_argument("--acceptance-evidence", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        return generate(REPOSITORY_ROOT, check=args.check, acceptance_evidence_path=args.acceptance_evidence)
    except (ContractError, OSError, ValueError) as error:
        print(f"BDD mirror generation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

