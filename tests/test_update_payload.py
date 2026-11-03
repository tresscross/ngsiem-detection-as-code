"""Regression tests for _build_update_payload's handling of inactive rules.

Falcon 400s when an update to an inactive rule carries schedule/start_on/stop_on
("can't be transitioned in state 'inactive' and also update attributes
'schedule', 'start_on' or 'stop_on'"). The payload builder must omit
schedule.definition for inactive rules while still sending it for active ones.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sync_detections import _build_update_payload  # noqa: E402


def _rule(status):
    return {
        "id": "abc",
        "name": "x",
        "status": status,
        "search": {"filter": "#a=1\n| groupBy(x)", "outcome": "detection",
                   "lookback": "1h", "trigger_mode": "summary"},
        "schedule": {"definition": "@every 1h0m"},
    }


def test_inactive_omits_schedule():
    payload = _build_update_payload(_rule("inactive"), "abc")
    assert "operation" not in payload, "inactive update must not carry schedule"
    assert payload["name"] == "x"  # other fields still sent


def test_active_includes_schedule():
    payload = _build_update_payload(_rule("active"), "abc")
    assert payload["operation"]["schedule"]["definition"] == "@every 1h0m"
