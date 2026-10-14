import json
import os
import sys
import time
from typing import Any

from detection.common.types import Severity
from ui.display import render_alert_panel, render_debug_flow

DEBUG_MODE = os.environ.get("DLP_DEBUG", "0").lower() in ("1", "true", "yes")


def log_debug(proto: str, src: str, dst: str) -> None:
    if not DEBUG_MODE:
        return
    render_debug_flow(protocol_name=proto, source_address=src, destination_address=dst)


def _emit_json(alert: dict[str, Any]) -> None:
    sys.stdout.write(f"[DLP-ALERT] {json.dumps(alert)}\n")
    sys.stdout.flush()


def log_alert(
    channel: str,
    rule_id: str,
    severity: Severity,
    source_ip: str,
    destination: str,
    details: dict[str, Any],
    blocked: bool = False,
    as_json: bool = False,
) -> None:
    alert = {
        "timestamp": time.time(),
        "channel": channel,
        "rule_id": rule_id,
        "severity": severity,
        "source_ip": source_ip,
        "destination": destination,
        "blocked": blocked,
        "details": details,
    }
    if as_json:
        _emit_json(alert)
    else:
        render_alert_panel(alert_telemetry_payload=alert)
