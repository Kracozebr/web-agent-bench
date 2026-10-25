#!/usr/bin/env python3
"""Audit semantic BDD contracts and adapter boundaries before acceptance runs."""

from __future__ import annotations

import argparse
import ast
import inspect
import json
import re
import sys
import textwrap
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from tests.bdd.adapters import build_registry
from tools.generate_bdd_mirrors import (
    expected_outputs,
    parse_specs,
    validate_generated_inventory,
)
from tools.harness_contracts import (
    load_manifest,
    load_proposal,
    validate_proposal_inventory,
    validate_spec_snapshot,
)


def _contains_scenario(node: ast.AST, scenario_id: str) -> bool:
    return any(isinstance(item, ast.Constant) and item.value == scenario_id for item in ast.walk(node))


def _scenario_sources(case: object, scenario_id: str) -> tuple[str, str]:
    """Return the scenario-specific execute and verify methods reachable on a case."""

    source = textwrap.dedent(inspect.getsource(case.__class__))
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    token = scenario_id.replace("-", "_")
    sources: dict[str, list[str]] = {"execute": [], "verify": []}
    for phase in sources:
        exact = functions.get(f"_{phase}_{token}")
        if exact is not None:
            sources[phase].append(ast.get_source_segment(source, exact) or "")
            continue
        phase_node = functions.get(phase)
        if phase_node is None:
            continue
        for branch in ast.walk(phase_node):
            if isinstance(branch, ast.If) and _contains_scenario(branch.test, scenario_id):
                sources[phase].append(ast.get_source_segment(source, branch) or "")
    return "\n".join(sources["execute"]), "\n".join(sources["verify"])


def _attribute_chain(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return list(reversed(parts))


def _private_application_calls(*sources: str) -> set[str]:
    """Find private application calls while allowing explicit contract exceptions."""

    calls: set[str] = set()
    aliases: dict[str, list[str]] = {}

    def expand(chain: list[str]) -> list[str]:
        return aliases.get(chain[0], [chain[0]]) + chain[1:]

    for source in sources:
        try:
            tree = ast.parse(textwrap.dedent(source))
        except SyntaxError:
            continue
        for node in sorted(ast.walk(tree), key=lambda item: getattr(item, "lineno", 0)):
            if isinstance(node, ast.Assign):
                value_chain = _attribute_chain(node.value)
                if value_chain is not None:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            aliases[target.id] = expand(value_chain)
            if not isinstance(node, ast.Call):
                continue
            chain = _attribute_chain(node.func)
            if chain is None:
                continue
            expanded = expand(chain)
            try:
                application_index = expanded.index("application")
            except ValueError:
                continue
            if any(part.startswith("_") for part in expanded[application_index + 1 :]):
                calls.add(".".join(expanded))
    return calls


def _audit_case(scenario_id: str, contract: Any, case: object) -> list[str]:
    errors: list[str] = []
    try:
        execution, verification = _scenario_sources(case, scenario_id)
    except (OSError, TypeError, IndentationError, SyntaxError) as error:
        return [f"{scenario_id}: cannot inspect adapter source: {error}"]

    if not execution or not verification:
        errors.append(f"{scenario_id}: missing scenario-specific execute/verify path")
    if "context.check(" not in verification:
        errors.append(f"{scenario_id}: verification has no named context.check observation")
    if not any(token in verification for token in ("assert ", "context.check(")):
        errors.append(f"{scenario_id}: verification has no meaningful assertion")

    observed = {
        name
        for name in re.findall(r"context\.(?:check|observe)\(\s*[\"']([^\"']+)", verification)
    }
    missing_observations = sorted(set(contract.required_observations) - observed)
    if missing_observations:
        errors.append(
            f"{scenario_id}: verification does not name required observations: {missing_observations}"
        )

    private_calls = sorted(_private_application_calls(execution, verification))
    allowed_private_calls = set(contract.allowed_private_calls)
    unexpected = sorted(set(private_calls) - allowed_private_calls)
    if unexpected:
        errors.append(f"{scenario_id}: undeclared private application calls: {unexpected}")
    missing_exceptions = sorted(allowed_private_calls - set(private_calls))
    if missing_exceptions:
        errors.append(
            f"{scenario_id}: manifest declares private calls absent from reachable source: {missing_exceptions}"
        )
    return errors


def audit(root: Path, change_name: str | None = None) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    scenarios = parse_specs(root, change_name)
    approved_ids = {scenario.scenario_id for scenario in scenarios}
    manifest, contracts = load_manifest(root, change_name)
    try:
        validate_spec_snapshot(root, scenarios, manifest, change_name)
    except ValueError as error:
        errors.append(str(error))

    proposal = None
    if change_name is not None:
        proposal = load_proposal(root, change_name)
        validate_proposal_inventory(proposal, scenarios, contracts)

    registry = None
    try:
        registry = build_registry(change_name)
    except (ImportError, ValueError, RuntimeError) as error:
        errors.append(f"cannot build selected adapter registry: {error}")
    registered_ids = set(registry.inventory()) if registry is not None else set()
    if registered_ids != approved_ids:
        errors.append(
            "adapter inventory drifted: "
            f"missing={sorted(approved_ids - registered_ids)}, "
            f"unexpected={sorted(registered_ids - approved_ids)}"
        )
    if change_name is not None and registry is not None and proposal is not None:
        expected_profiles = {
            scenario_id: row["adapter"]
            for scenario_id, row in proposal["protected_scenarios"].items()
        }
        actual_profiles = registry.adapter_profiles()
        if actual_profiles != expected_profiles:
            errors.append(
                "adapter profile inventory drifted: "
                f"missing={sorted(set(expected_profiles) - set(actual_profiles))}, "
                f"unexpected={sorted(set(actual_profiles) - set(expected_profiles))}, "
                f"mismatched={sorted(scenario_id for scenario_id in set(actual_profiles) & set(expected_profiles) if actual_profiles[scenario_id] != expected_profiles[scenario_id])}"
            )

    if change_name is not None:
        mirror_outputs = {
            path: content
            for path, content in expected_outputs(root, scenarios, change_name=change_name).items()
            if path.name != "scenario-map.md"
        }
        stale_mirrors = validate_generated_inventory(root, mirror_outputs, change_name)
        if stale_mirrors:
            errors.append(
                "active feature/mapper inventory drifted: "
                f"{[path.relative_to(root).as_posix() for path in stale_mirrors]}"
            )

    contract_ids = set(contracts)
    for scenario_id in sorted(contract_ids - approved_ids):
        errors.append(f"contract declares unknown scenario: {scenario_id}")
    for scenario_id in sorted(contract_ids & approved_ids & registered_ids):
        assert registry is not None
        errors.extend(_audit_case(scenario_id, contracts[scenario_id], registry.cases()[scenario_id]))

    unprotected = sorted(approved_ids - contract_ids)
    coverage_policy = manifest.get("coverage_policy", {})
    required_protected = set(coverage_policy.get("required_protected_scenarios", []))
    if required_protected != contract_ids:
        errors.append(
            "coverage policy does not equal the protected scenario set: "
            f"missing={sorted(contract_ids - required_protected)}, "
            f"extra={sorted(required_protected - contract_ids)}"
        )
    actual_coverage_status = "complete" if not unprotected else "partial"
    if coverage_policy.get("status") != actual_coverage_status:
        errors.append(
            "coverage policy status is stale: "
            f"declared={coverage_policy.get('status')!r}, actual={actual_coverage_status!r}"
        )
    if unprotected:
        warnings.append(f"{len(unprotected)} approved scenarios remain outside protected contracts")
    return {
        "change": change_name or "web3-agent-bench-baseline",
        "normative_source": (
            f"openspec/changes/{change_name}/specs/*/spec.md"
            if change_name is not None
            else "openspec/specs/*/spec.md"
        ),
        "status": "failed" if errors else "passed",
        "coverage_status": actual_coverage_status,
        "protected_scenarios": len(contract_ids & approved_ids),
        "approved_scenarios": len(approved_ids),
        "unprotected_scenarios": unprotected,
        "warnings": warnings,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--change",
        default=None,
        help="select one active OpenSpec change; omit to audit synchronized main specs",
    )
    args = parser.parse_args(argv)
    try:
        report = audit(REPOSITORY_ROOT, args.change)
    except (OSError, ValueError, RuntimeError, ImportError) as error:
        report = {
            "change": args.change or "web3-agent-bench-baseline",
            "status": "failed",
            "protected_scenarios": 0,
            "approved_scenarios": 0,
            "unprotected_scenarios": [],
            "warnings": [],
            "errors": [str(error)],
        }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"BDD harness audit {report['status']}: "
            f"{report['protected_scenarios']}/{report['approved_scenarios']} scenarios protected"
        )
        for warning in report["warnings"]:
            print(f"warning: {warning}")
        for error in report["errors"]:
            print(f"error: {error}", file=sys.stderr)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

