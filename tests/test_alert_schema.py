"""Alerts built by encdetect.alert must conform to the frozen shared schema."""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from encdetect.alert import Alert, Evidence, FlowId  # noqa: E402

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "alert_schema.json"


def _sample_alert() -> dict:
    return Alert(
        flow_id=FlowId("10.0.0.5", 51344, "203.0.113.9", 443, "tcp"),
        severity="high",
        confidence=0.87,
        window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        window_end=datetime(2026, 1, 1, 0, 0, 25, tzinfo=timezone.utc),
        evidence=[
            Evidence("ja4", "t13d1516h2_8daaf6152771_b186095e22b6", 0.31),
            Evidence("iat_std_ms", 12.4, 0.22),
        ],
    ).to_dict()


def test_required_fields_present():
    alert = _sample_alert()
    schema = json.loads(SCHEMA_PATH.read_text())
    for field in schema["required"]:
        assert field in alert, f"missing required field: {field}"


def test_severity_and_confidence_distinct():
    alert = _sample_alert()
    assert alert["severity"] == "high"          # inherent impact
    assert 0.0 <= alert["confidence"] <= 1.0    # model certainty
    assert alert["severity"] != alert["confidence"]


def test_detector_id_constant():
    assert _sample_alert()["detector"] == "encrypted_session_v1"


def test_validates_against_jsonschema_if_available():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(instance=_sample_alert(), schema=schema)
