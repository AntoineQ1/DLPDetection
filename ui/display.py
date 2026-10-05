"""Terminal Presentation and User Interface Abstraction Layer.

This module provides a unified interface for rendering rich terminal graphics,
telemetry panels, and real-time execution feedback. It leverages the Rich
library under the hood to ensure visually engaging outputs while abstracting
presentation complexity away from core networking logic.

THIS FILE IS AI GENERATED.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.traceback import install

# Global console instance used for all standard output operations
shared_console: Console = Console(highlight=False)

# Install rich traceback handler to enhance post-mortem debugging experiences
install(show_locals=False)

# Color mapping dictionary defining terminal palette per severity tier
ALERT_SEVERITY_COLOR_PALETTE: dict[str, str] = {
    "low": "green",
    "medium": "yellow",
    "high": "bold orange3",
    "critical": "bold red",
}

# Constants for preview formatting constraints
HEX_PREVIEW_BYTE_LIMIT: int = 24
ASCII_PREVIEW_BYTE_LIMIT: int = 48


# =====================================================================
# Status Indicators & Logging Helper Functions
# =====================================================================


def print_status(status_message: str) -> None:
    """Displays a standardized in-progress operational message to the user.

    Parameters:
        status_message (str): The informational text describing the ongoing task.
    """
    shared_console.print(f"  [bold cyan]➜[/] {status_message}")


def print_success(success_message: str) -> None:
    """Displays a positive confirmation indicating successful task completion.

    Parameters:
        success_message (str): The success notice to present to the user.
    """
    shared_console.print(f"  [bold green]✔[/] {success_message}\n")


def print_hint(guidance_message: str) -> None:
    """Renders contextual advice or next-step hints for demonstration observers.

    Parameters:
        guidance_message (str): Informational hint or verification suggestion.
    """
    shared_console.print(f"  [dim]➔ {guidance_message}[/]\n")


def render_debug_flow(
    protocol_name: str,
    source_address: str,
    destination_address: str,
) -> None:
    """Renders a single lightweight audit log entry for network flow tracking.

    Parameters:
        protocol_name (str): The layer 3 or layer 4 protocol identifier (e.g. 'ICMP').
        source_address (str): The originating host IP address.
        destination_address (str): The recipient target IP address.
    """
    current_utc_clock: str = datetime.now(UTC).strftime("%H:%M:%S")
    shared_console.print(
        f"[dim]{current_utc_clock} · [cyan]{protocol_name:<4}[/] "
        f"{source_address} → {destination_address}[/]"
    )


# =====================================================================
# Attack Scenario Visual Panels
# =====================================================================


def render_attack_banner(
    target: str,
    scenario_mode: str,
    scenario_description: str,
    expected_alert_identifier: str,
) -> None:
    """Renders an executive presentation header summarizing the active attack scenario.

    Parameters:
        target (str): Destination network sink IP address.
        scenario_mode (str): Name of the active attack strategy.
        scenario_description (str): Functional goal and mechanism summary.
        expected_alert_identifier (str): Expected DLP detection signature and severity.
    """
    # Initialize a grid table for alignment
    metadata_grid = Table.grid(padding=(0, 2))
    metadata_grid.add_column(style="bold cyan", justify="right")
    metadata_grid.add_column()

    # Populate rows with scenario parameters
    metadata_grid.add_row("Scenario", f"[bold magenta]{scenario_mode.upper()}[/]")
    metadata_grid.add_row("Objective", scenario_description)
    metadata_grid.add_row("Target", f"[yellow]{target}[/] (Attacker Sink)")
    metadata_grid.add_row("Expected", f"[red]{expected_alert_identifier}[/]")

    # Print framed banner panel to the console
    shared_console.print()
    shared_console.print(
        Panel(
            metadata_grid,
            title="[bold yellow]DLP EVALUATION ATTACK SUITE[/] [dim]:: ICMP Covert Channel[/]",
            border_style="cyan",
            expand=False,
        )
    )
    shared_console.print()


def render_payload_telemetry(
    raw_payload_bytes: bytes,
    panel_title: str = "Payload Inspection",
) -> None:
    """Constructs a dual hexadecimal and sanitized ASCII preview of packet buffers.

    Parameters:
        raw_payload_bytes (bytes): The raw byte sequence encapsulated in the frame.
        panel_title (str): Descriptive label placed on the panel border.
    """
    # Extract hexadecimal representation up to the preview limit
    hexadecimal_representation: str = " ".join(
        f"{byte_value:02x}" for byte_value in raw_payload_bytes[:HEX_PREVIEW_BYTE_LIMIT]
    )
    if len(raw_payload_bytes) > HEX_PREVIEW_BYTE_LIMIT:
        hexadecimal_representation += " ..."

    # Sanitize characters into readable ASCII, replacing non-printables with dots
    sanitized_ascii_string: str = "".join(
        chr(byte_val) if 32 <= byte_val < 127 else "."
        for byte_val in raw_payload_bytes[:ASCII_PREVIEW_BYTE_LIMIT]
    )

    # Assemble structured inspection table
    inspection_table = Table.grid(padding=(0, 2))
    inspection_table.add_column(style="bold", justify="right")
    inspection_table.add_column()
    inspection_table.add_row("Total Size", f"[yellow]{len(raw_payload_bytes)} bytes[/]")
    inspection_table.add_row("Hex Preview", f"[dim]{hexadecimal_representation}[/]")
    inspection_table.add_row("ASCII Decoded", f"[green]{sanitized_ascii_string}[/]")

    # Output panel to screen
    shared_console.print(
        Panel(
            inspection_table,
            title=f"[bold]{panel_title}[/]",
            border_style="blue",
            expand=False,
        )
    )
    shared_console.print()


class BurstProgressTracker:
    """A context-manager implementation that coordinates terminal progress animations.

    This class encapsulates rich progress mechanics to facilitate real-time visual
    tracking of high-frequency packet emissions without leaking presentation details.
    """

    def __init__(
        self,
        total_packet_count: int,
        task_description: str = "Burst Stream",
    ) -> None:
        """Initializes the underlying Rich Progress orchestration components.

        Parameters:
            total_packet_count (int): Aggregate number of packets to transmit.
            task_description (str): Label associated with the animated task bar.
        """
        self.total_packets: int = total_packet_count
        self.task_description: str = task_description
        self._progress_controller: Progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=shared_console,
        )
        self._active_task_identifier: Any = None

    def __enter__(self) -> Self:
        """Activates the live progress display loop upon entering context."""
        self._progress_controller.start()
        self._active_task_identifier = self._progress_controller.add_task(
            self.task_description,
            total=self.total_packets,
        )
        return self

    def step(self, packet_sequence_index: int, payload_size_in_bytes: int) -> None:
        """Increments the progress tracker and displays intermediate packet telemetry.

        Parameters:
            packet_sequence_index (int): Zero-indexed sequence number of the transmitted packet.
            payload_size_in_bytes (int): Length of the raw data payload transmitted.
        """
        current_timestamp: str = time.strftime("%H:%M:%S")
        self._progress_controller.console.print(
            f"  [cyan]{packet_sequence_index + 1:02d}/{self.total_packets:02d}[/] "
            f"[dim]{current_timestamp}[/] → "
            f"Sent Echo [bold]Seq={packet_sequence_index:03d}[/] ({payload_size_in_bytes}B)"
        )
        self._progress_controller.advance(self._active_task_identifier)

    def __exit__(
            self,
            exception_type: type[BaseException] | None,
            exception_value: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            """Gracefully halts the progress controller on context exit.

            Parameters:
                exception_type (type[BaseException] | None): The exception class if an error occurred.
                exception_value (BaseException | None): The exception instance raised, if any.
                traceback (TracebackType | None): The traceback object associated with the exception.
            """
            self._progress_controller.stop()


# =====================================================================
# DLP Incident Report & Security Panel
# =====================================================================


def _serialize_detail_attribute(attribute_value: Any) -> str:
    """Helper method to ensure compound detail values are serialized cleanly.

    Parameters:
        attribute_value (Any): The arbitrary value to format for display.

    Returns:
        str: Stringified representation optimized for inline visual scanning.
    """
    if isinstance(attribute_value, (dict, list)):
        return json.dumps(attribute_value, separators=(", ", ":"))
    return str(attribute_value)


def render_alert_panel(alert_telemetry_payload: dict[str, Any]) -> None:
    """Renders a fully styled DLP security notification card.

    Interprets incident metadata, formats security severities, evaluates mitigation
    status (blocked vs allowed), and prints a color-coded inspection card.

    Parameters:
        alert_telemetry_payload (dict[str, Any]): Dictionary containing security event attributes.
    """
    # Extract and normalize severity key
    raw_severity = alert_telemetry_payload.get("severity", "low")
    normalized_severity_key: str = (
        raw_severity.value if hasattr(raw_severity, "value") else str(raw_severity)
    ).lower()

    # Determine visual accents based on severity and enforcement action
    card_border_color: str = ALERT_SEVERITY_COLOR_PALETTE.get(
        normalized_severity_key,
        "bright_blue",
    )
    event_timestamp: float = alert_telemetry_payload.get("timestamp", time.time())
    formatted_event_clock: str = datetime.fromtimestamp(
        event_timestamp, tz=UTC
    ).strftime("%H:%M:%S")

    is_transmission_blocked: bool = alert_telemetry_payload.get("blocked", False)
    status_badge: str = (
        "[bold white on red] BLOCKED [/]"
        if is_transmission_blocked
        else "[bold black on green] ALLOWED [/]"
    )
    status_icon: str = "⛔" if is_transmission_blocked else "⚠️"
    rule_identifier: str = alert_telemetry_payload.get("rule_id", "GENERIC_DETECTION")

    card_title: str = (
        f"{status_icon}  [{card_border_color}]{normalized_severity_key.upper()}[/] "
        f"[bold white]{rule_identifier}[/] {status_badge}"
    )

    # Build internal structured content grid
    content_layout_grid = Table.grid(padding=(0, 2))
    content_layout_grid.add_column(style="dim bold", justify="right")
    content_layout_grid.add_column()

    # Network vector details
    source_ip: str = alert_telemetry_payload.get("source_ip", "0.0.0.0")
    destination_ip: str = alert_telemetry_payload.get("destination", "0.0.0.0")
    detection_channel: str = alert_telemetry_payload.get("channel", "NETWORK")
    flow_representation: str = (
        f"[cyan]{source_ip}[/] [dim]→[/] [cyan]{destination_ip}[/]"
    )

    content_layout_grid.add_row(
        "Flow",
        f"{flow_representation}  [dim]({formatted_event_clock} · {detection_channel})[/]",
    )

    # Extract optional descriptive message
    mutable_details_copy: dict[str, Any] = dict(
        alert_telemetry_payload.get("details", {})
    )
    custom_description: str | None = mutable_details_copy.pop("description", None)
    if custom_description:
        content_layout_grid.add_row("Alert", f"[bold white]{custom_description}[/]")

    # Append remaining contextual metadata attributes if present
    if mutable_details_copy:
        formatted_parameters: str = "   ".join(
            f"[dim]{param_key}=[/][bright_cyan]{_serialize_detail_attribute(param_val)}[/]"
            for param_key, param_val in mutable_details_copy.items()
        )
        content_layout_grid.add_row("Details", formatted_parameters)

    # Render complete card to terminal
    shared_console.print(
        Panel(
            content_layout_grid,
            title=card_title,
            title_align="left",
            border_style=card_border_color,
            box=box.ROUNDED,
            expand=False,
            padding=(0, 1),
        )
    )
