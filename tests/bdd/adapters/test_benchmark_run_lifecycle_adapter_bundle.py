from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.bdd.adapters import ScenarioContext
from tests.bdd.adapters import benchmark_run_lifecycle as adapter


SCENARIOS = ("BRL-SC-023", "BRL-SC-024", "BRL-SC-025")


class BenchmarkRunLifecycleGenericBundleTests(unittest.TestCase):
    def _prepare_root(self, root: Path) -> tuple[dict, dict, dict[str, str]]:
        proposal_path = root / "openspec" / "changes" / adapter.CHANGE_NAME / "bdd-harness-proposal.json"
        proposal_path.parent.mkdir(parents=True)
        shutil.copyfile(adapter.PROPOSAL_PATH, proposal_path)
        contract_root = root / "tests" / "bdd" / "changes" / adapter.CHANGE_NAME
        contract_root.mkdir(parents=True)
        shutil.copyfile(adapter.PROPOSAL_PATH, contract_root / "bdd-harness-proposal.json")
        shutil.copyfile(adapter.CONTRACT_PATH, contract_root / "harness-contracts.json")

        source_relative = "tests/bdd/adapters/benchmark_run_lifecycle.py"
        source = root / source_relative
        source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(adapter.__file__), source)
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        producer = root / "src" / "producer.mjs"
        producer.parent.mkdir(parents=True)
        producer.write_text("original-producer", encoding="utf-8")
        inventory = {source_relative: source_hash, "src/producer.mjs": hashlib.sha256(producer.read_bytes()).hexdigest()}

        packages = root / "packages" / "owner-acceptance" / "src"
        packages.mkdir(parents=True)
        shutil.copyfile(
            Path(adapter.REPOSITORY_ROOT) / "packages" / "owner-acceptance" / "src" / "evidence.mjs",
            packages / "evidence.mjs",
        )
        shutil.copyfile(
            Path(adapter.REPOSITORY_ROOT) / "packages" / "owner-acceptance" / "src" / "bdd-evidence.mjs",
            packages / "bdd-evidence.mjs",
        )
        proposal, contract, _ = adapter._load_contract_sources()
        return proposal, contract, inventory

    def _write_with_generic_writer(self, root: Path, captures: dict, status: str) -> None:
        writer_url = (Path(adapter.REPOSITORY_ROOT) / "packages" / "owner-acceptance" / "src" / "bdd-evidence.mjs").as_uri()
        provenance = {
            "sourceStableDuringRun": True,
            "inputHashesBefore": getattr(self, "inventory"),
            "inputHashesAfter": getattr(self, "inventory"),
        }
        encoded_root = json.dumps(str(root))
        encoded_writer = json.dumps(writer_url)
        encoded_captures = json.dumps(captures)
        encoded_provenance = json.dumps(provenance)
        source = f"""
          const {{ saveBenchmarkBddEvidence }} = await import({encoded_writer});
          const root = {encoded_root};
          const captures = {encoded_captures};
          const provenance = {encoded_provenance};
          for (const [scenarioId, capture] of Object.entries(captures)) {{
            await saveBenchmarkBddEvidence({{
              repositoryRoot: root,
              changeName: 'benchmark-run-lifecycle',
              scenarioId,
              capture,
              provenance,
              status: {json.dumps(status)},
              reasonCode: 'fixture_incomplete',
            }});
          }}
        """
        subprocess.run(["node", "--input-type=module", "-e", source], check=True, capture_output=True, text=True)

    def _raw_capture(self, scenario_id: str) -> dict:
        if scenario_id in {"BRL-SC-023", "BRL-SC-024"}:
            return {"schemaVersion": "benchmark-run-lifecycle-runtime-evidence/v1", "scenarioId": scenario_id}
        return {
            "schemaVersion": "benchmark-run-lifecycle-codex-runtime-evidence/v1",
            "scenarioId": scenario_id,
            "client": {},
            "launchCaptures": {},
            "observations": {},
        }

    def test_generic_writer_bundles_are_loaded_and_cannot_pass_without_complete_raw_facts(self):
        with tempfile.TemporaryDirectory(prefix="brl-generic-bundle-") as temporary:
            root = Path(temporary)
            proposal, contract, self.inventory = self._prepare_root(root)
            self._write_with_generic_writer(root, {scenario_id: self._raw_capture(scenario_id) for scenario_id in SCENARIOS}, "passed")

            with (
                patch.object(adapter, "REPOSITORY_ROOT", root),
                patch.object(adapter, "EVIDENCE_ROOT", root / "artifacts" / "runs" / "acceptance"),
                patch.object(adapter, "CHANGE_ROOT", root / "openspec" / "changes" / adapter.CHANGE_NAME),
                patch.object(adapter, "PROPOSAL_PATH", root / "openspec" / "changes" / adapter.CHANGE_NAME / "bdd-harness-proposal.json"),
                patch.object(adapter, "CONTRACT_PATH", root / "tests" / "bdd" / "changes" / adapter.CHANGE_NAME / "harness-contracts.json"),
            ):
                for scenario_id in SCENARIOS:
                    manifest, artifacts = adapter._load_run(scenario_id)
                    self.assertEqual(manifest["status"], "passed")
                    self.assertIn("runtime-evidence.json", artifacts)
                    case = adapter.ExplicitBenchmarkRunLifecycleEvidenceCase(
                        scenario_id,
                        proposal["protected_scenarios"][scenario_id],
                        contract["protected_scenarios"][scenario_id],
                    )
                    with self.subTest(scenario_id=scenario_id), self.assertRaises(AssertionError):
                        case._execute_bound(ScenarioContext(scenario_id), scenario_id)

    def test_generic_writer_blocked_capture_remains_blocked_in_the_adapter(self):
        with tempfile.TemporaryDirectory(prefix="brl-blocked-bundle-") as temporary:
            root = Path(temporary)
            proposal, contract, self.inventory = self._prepare_root(root)
            self._write_with_generic_writer(root, {"BRL-SC-025": self._raw_capture("BRL-SC-025")}, "blocked")
            (root / "src" / "producer.mjs").write_text("later-producer", encoding="utf-8")

            with (
                patch.object(adapter, "REPOSITORY_ROOT", root),
                patch.object(adapter, "EVIDENCE_ROOT", root / "artifacts" / "runs" / "acceptance"),
                patch.object(adapter, "CHANGE_ROOT", root / "openspec" / "changes" / adapter.CHANGE_NAME),
                patch.object(adapter, "PROPOSAL_PATH", root / "openspec" / "changes" / adapter.CHANGE_NAME / "bdd-harness-proposal.json"),
                patch.object(adapter, "CONTRACT_PATH", root / "tests" / "bdd" / "changes" / adapter.CHANGE_NAME / "harness-contracts.json"),
            ):
                case = adapter.ExplicitBenchmarkRunLifecycleEvidenceCase(
                    "BRL-SC-025",
                    proposal["protected_scenarios"]["BRL-SC-025"],
                    contract["protected_scenarios"]["BRL-SC-025"],
                )
                with self.assertRaises(pytest.skip.Exception):
                    case._execute_bound(ScenarioContext("BRL-SC-025"), "BRL-SC-025")


if __name__ == "__main__":
    unittest.main()
