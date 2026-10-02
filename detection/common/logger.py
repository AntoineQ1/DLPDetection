from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from detection.common.types import Severity

console = Console(highlight=False)

SEVERITY_COLORS: dict[str, str] = {
    "low": "green",
    "medium": "yellow",
    "high": "bold orange3",
    "critical": "bold red",
}

DEBUG_MODE = os.environ.get("DLP_DEBUG", "0").lower() in ("1", "true", "yes")


def log_debug(proto: str, src: str, dst: str) -> None:
    if not DEBUG_MODE:
        return
    clock = datetime.now(UTC).strftime("%H:%M:%S")
    console.print(f"[dim]{clock} · [cyan]{proto:<4}[/] {src} → {dst}[/]")


def _format_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(", ", ":"))
    return str(value)


def _get_severity_name(severity: Any) -> str:
    val = severity.value if hasattr(severity, "value") else str(severity)
    return str(val).lower()


def _render_alert(alert: dict[str, Any]) -> None:
    clock = datetime.fromtimestamp(alert["timestamp"], tz=UTC).strftime("%H:%M:%S")
    sev_key = _get_severity_name(alert["severity"])
    border_color = SEVERITY_COLORS.get(sev_key, "bright_blue")

    if alert["blocked"]:
        badge = "[bold white on red] BLOCKED [/]"
    else:
        badge = "[bold black on green] ALLOWED [/]"

    icon = "⛔" if alert["blocked"] else "⚠️"
    title = f"{icon}  [{border_color}]{sev_key.upper()}[/] [bold white]{alert['rule_id']}[/] {badge}"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim bold", justify="right")
    grid.add_column()

    flow = f"[cyan]{alert['source_ip']}[/] [dim]→[/] [cyan]{alert['destination']}[/]"
    grid.add_row("Flow", f"{flow}  [dim]({clock} · {alert['channel']})[/]")

    details = dict(alert.get("details", {}))
    description = details.pop("description", None)
    if description:
        grid.add_row("Alert", f"[bold white]{description}[/]")

    if details:
        params_str = "   ".join(
            f"[dim]{k}=[/][bright_cyan]{_format_value(v)}[/]"
            for k, v in details.items()
        )
        grid.add_row("Details", params_str)

    console.print(
        Panel(
            grid,
            title=title,
            title_align="left",
            border_style=border_color,
            box=box.ROUNDED,
            expand=False,
            padding=(0, 1),
        )
    )


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
        _render_alert(alert)
