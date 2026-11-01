import hashlib
import json
from pathlib import Path

import pytest

from tests.bdd.adapters.participant_cabinet_replay import money_summary, verify_capture


def test_money_replay_uses_integer_precision_and_preserves_small_refunds():
    assert money_summary(1) == "<0.01"
    assert money_summary(-1) == "-<0.01"
    assert money_summary(0) == "0.00"
    assert money_summary(1004999) == "1.00"
    assert money_summary(1005000) == "1.01"
    assert money_summary(-1005000) == "-1.01"
    assert money_summary(9007199254740993123456) == "9007199254740993.12"


def test_producer_pass_labels_do_not_replace_source_and_observer_proof(tmp_path: Path):
    payload = {"schemaVersion": "pcu-browser-boundary-capture/v1", "status": "passed",
               "facts": {"allEightPassed": True}, "provenance": {"sourceStableDuringRun": True}}
    raw = json.dumps(payload).encode()
    (tmp_path / "capture.json").write_bytes(raw)
    with pytest.raises(AssertionError, match="source inventory"):
        verify_capture(tmp_path, {"path": "capture.json", "sha256": hashlib.sha256(raw).hexdigest()})


def test_capture_tamper_is_rejected_before_any_replay(tmp_path: Path):
    raw = b'{"schemaVersion":"pcu-browser-boundary-capture/v1"}'
    (tmp_path / "capture.json").write_bytes(raw + b" ")
    with pytest.raises(AssertionError, match="hash"):
        verify_capture(tmp_path, {"path": "capture.json", "sha256": hashlib.sha256(raw).hexdigest()})
