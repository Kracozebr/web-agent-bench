"""Active-delta adapter preflight must distinguish absence from import failure."""

from __future__ import annotations

import pytest

from tools.run_bdd_acceptance import _active_adapter_spec


def test_exact_missing_adapter_module_is_classified_as_absent() -> None:
    module_name = "tests.bdd.adapters.benchmark_run_lifecycle"

    def find_missing_module(requested_name: str) -> None:
        assert requested_name == module_name
        raise ModuleNotFoundError(f"No module named {requested_name!r}", name=requested_name)

    assert _active_adapter_spec(module_name, find_missing_module) is None


def test_unrelated_importerror_is_not_reclassified_as_missing_adapter() -> None:
    module_name = "tests.bdd.adapters.benchmark_run_lifecycle"

    def find_module_with_missing_dependency(requested_name: str) -> None:
        assert requested_name == module_name
        raise ModuleNotFoundError("No module named 'runtime_dependency'", name="runtime_dependency")

    with pytest.raises(ModuleNotFoundError) as error:
        _active_adapter_spec(module_name, find_module_with_missing_dependency)

    assert error.value.name == "runtime_dependency"
