"""
Event log loader module for NetForensics.
Parses events.log entries into structured representations without inferring root cause.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Union

from .exceptions import EventLogNotFoundError, InvalidEventLogError


@dataclass
class EventLogEntry:
    """Structured representation of a single log event entry."""
    timestamp: str
    device: str
    severity: str
    event_type: Union[str, None]
    interface: Union[str, None]
    details: Union[str, None]
    raw: str
    line_number: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "device": self.device,
            "severity": self.severity,
            "event_type": self.event_type,
            "interface": self.interface,
            "details": self.details,
            "raw": self.raw,
            "line_number": self.line_number,
        }


def parse_log_line(line: str, line_number: int) -> Union[EventLogEntry, None]:
    """
    Parses a single line from an events.log file.

    Format: <timestamp> <device> <severity> [interface] [event_type/details]
    """
    stripped = line.strip()
    if not stripped:
        return None

    parts = stripped.split()
    if len(parts) < 3:
        raise InvalidEventLogError(
            f"Malformed log entry at line {line_number}: expected at least timestamp, device, and severity. Got '{stripped}'"
        )

    timestamp = parts[0]
    device = parts[1]
    severity = parts[2]

    rem = parts[3:]
    interface: Union[str, None] = None
    event_type: Union[str, None] = None
    details_str = ""

    if rem:
        first_rem = rem[0]
        # Detect if first remainder item is an interface name (e.g., Gi0/1, eth0, Fa0/1, etc.)
        is_interface = (
            any(first_rem.lower().startswith(prefix) for prefix in ("gi", "eth", "fa", "te", "en", "port", "vlan"))
            or "/" in first_rem
        )

        if is_interface and len(rem) > 1:
            interface = first_rem
            event_type = rem[1]
            details_str = " ".join(rem[2:]) if len(rem) > 2 else ""
        else:
            event_type = first_rem
            details_str = " ".join(rem[1:]) if len(rem) > 1 else ""

        # Extract interface if specified as a key-value pair (e.g., interface=Gi0/1)
        if not interface and details_str:
            for item in details_str.split():
                if item.startswith("interface="):
                    interface = item.split("=", 1)[1]
                    break

    return EventLogEntry(
        timestamp=timestamp,
        device=device,
        severity=severity,
        event_type=event_type,
        interface=interface,
        details=details_str if details_str else None,
        raw=line.strip("\r\n"),
        line_number=line_number,
    )


def load_events(file_path: Union[str, Path]) -> List[EventLogEntry]:
    """
    Loads and parses an events.log file.

    Args:
        file_path: Path to the events.log file.

    Returns:
        List of parsed EventLogEntry objects.

    Raises:
        EventLogNotFoundError: If the file does not exist.
        InvalidEventLogError: If the log file cannot be read or contains malformed lines.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise EventLogNotFoundError(f"Event log file not found: {path}")

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        raise InvalidEventLogError(f"Could not read event log file '{path}': {exc}") from exc

    entries: List[EventLogEntry] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        entry = parse_log_line(line, idx)
        if entry is not None:
            entries.append(entry)

    return entries
