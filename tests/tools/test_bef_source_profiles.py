from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tests.bdd.adapters.benchmark_environment_feasibility import (
    _replay_source_bindings_match,
    _replay_source_profile,
)
from tools.replay_bef_evidence import (
    REPOSITORY_ROOT,
    ReplayInputError,
    _approved_inputs,
    _select_source_profile,
)
from tools.run_bdd_acceptance import _acceptance_child_environment


def test_replay_profiles_bind_active_and_synced_main_sources_without_mixing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _, _, main_sources = _approved_inputs(REPOSITORY_ROOT, "BEF-SC-012", "synced-main")

    assert set(main_sources) == {"harnessContract", "normativeSpec", "predicateSource"}
    assert main_sources["harnessContract"]["path"] == "tests/bdd/harness-contracts.json"
    assert main_sources["normativeSpec"]["path"] == "openspec/specs/benchmark-environment-feasibility/spec.md"
    assert "proposal" not in main_sources

    replayer_path = REPOSITORY_ROOT / "tools/replay_bef_evidence.py"
    main_replayer_binding = {
        "replayerSourcePath": "tools/replay_bef_evidence.py",
        "replayerSourceSha256": hashlib.sha256(replayer_path.read_bytes()).hexdigest(),
    }
    active_root = tmp_path / "active-profile-fixture"
    active_sources = {}
    active_paths = {
        "proposal": "openspec/changes/benchmark-environment-feasibility/bdd-harness-proposal.json",
        "harnessContract": "tests/bdd/changes/benchmark-environment-feasibility/harness-contracts.json",
        "normativeSpec": "openspec/changes/benchmark-environment-feasibility/specs/benchmark-environment-feasibility/spec.md",
        "predicateSource": "tests/bdd/adapters/benchmark_environment_feasibility.py",
    }
    for name, relative in active_paths.items():
        file_path = active_root / relative
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(f"synthetic active binding for {name}\n", encoding="utf-8")
        active_sources[name] = {
            "path": relative,
            "sha256": hashlib.sha256(file_path.read_bytes()).hexdigest(),
        }
    active_replayer = active_root / "tools/replay_bef_evidence.py"
    active_replayer.parent.mkdir(parents=True, exist_ok=True)
    active_replayer.write_bytes(b"synthetic active replayer\n")
    active_replayer_binding = {
        "replayerSourcePath": "tools/replay_bef_evidence.py",
        "replayerSourceSha256": hashlib.sha256(active_replayer.read_bytes()).hexdigest(),
    }
    active_report = {
        **active_replayer_binding,
        "sourceProfile": "active-delta/v1",
        "approvedSources": active_sources,
    }
    main_report = {
        **main_replayer_binding,
        "sourceProfile": "synced-main/v1",
        "approvedSources": main_sources,
    }
    assert _replay_source_profile(active_report) == "active-delta"
    assert _replay_source_profile(main_report) == "synced-main"

    monkeypatch.setenv("BEF_SPEC_PROFILE", "active-delta")
    assert _replay_source_bindings_match(active_root, active_report)
    monkeypatch.setenv("BEF_SPEC_PROFILE", "synced-main")
    assert _replay_source_bindings_match(REPOSITORY_ROOT, main_report)
    assert not _replay_source_bindings_match(active_root, active_report)
    assert not _replay_source_bindings_match(
        REPOSITORY_ROOT,
        {
            **main_replayer_binding,
            "sourceProfile": "synced-main/v1",
            "approvedSources": {
                **main_sources,
                "proposal": {
                    "path": active_paths["proposal"],
                    "sha256": active_sources["proposal"]["sha256"],
                },
            },
        },
    )
    assert not _replay_source_bindings_match(
        REPOSITORY_ROOT,
        {**main_replayer_binding, "approvedSources": main_sources},
    )


def test_legacy_report_without_profile_keeps_active_delta_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BEF_SPEC_PROFILE", raising=False)
    assert _replay_source_profile({"approvedSources": {}}) == "active-delta"
    assert _select_source_profile() == "active-delta"


def test_replay_profile_selection_rejects_cli_environment_downgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEF_SPEC_PROFILE", "synced-main")
    assert _select_source_profile() == "synced-main"
    assert _select_source_profile("synced-main") == "synced-main"
    with pytest.raises(ReplayInputError, match="source_profile_conflict"):
        _select_source_profile("active-delta")


def test_acceptance_child_environment_authoritatively_tracks_selected_spec() -> None:
    caller_environment = {"BEF_SPEC_PROFILE": "active-delta", "UNCHANGED": "yes"}
    main_environment = _acceptance_child_environment(None, caller_environment)
    delta_environment = _acceptance_child_environment("benchmark-environment-feasibility", caller_environment)

    assert main_environment["BEF_SPEC_PROFILE"] == "synced-main"
    assert delta_environment["BEF_SPEC_PROFILE"] == "active-delta"
    assert main_environment["UNCHANGED"] == "yes"
    assert caller_environment["BEF_SPEC_PROFILE"] == "active-delta"


def test_bef_wrapper_main_mode_omits_change_and_restores_profile() -> None:
    wrapper_path = REPOSITORY_ROOT / "infrastructure/benchmark-environment/run-bdd.ps1"
    wrapper = wrapper_path.read_text(encoding="utf-8")

    assert "[switch]$SyncedMain" in wrapper
    assert "'BEF_SPEC_PROFILE'" in wrapper
    assert "$env:BEF_SPEC_PROFILE = 'synced-main'" in wrapper
    assert "$arguments = @('tools/run_bdd_acceptance.py')" in wrapper
    assert "if (-not $SyncedMain) { $arguments += @('--change', 'benchmark-environment-feasibility') }" in wrapper
    assert "'tests/bdd/mappers', 'tests/bdd/traceability'" in wrapper
    assert "foreach ($name in $names) {" in wrapper


def test_source_profile_environment_rejects_unknown_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEF_SPEC_PROFILE", "active-delta/something-else")
    with pytest.raises(ReplayInputError, match="source_profile_invalid"):
        _select_source_profile()
