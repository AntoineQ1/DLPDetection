import json
import sys
import time
from typing import Any


def log_alert(
    channel: str,
    rule_id: str,
    severity: str,
    source_ip: str,
    destination: str,
    details: dict[str, Any],
    blocked: bool = False,
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
    sys.stdout.write(f"[DLP-ALERT] {json.dumps(alert)}\n")
    sys.stdout.flush()