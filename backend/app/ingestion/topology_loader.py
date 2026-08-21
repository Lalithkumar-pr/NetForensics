"""
Topology loader module for NetForensics.
Reads and validates topology.json files without modifying data or building graph models.
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Union

from .exceptions import InvalidTopologyError, TopologyNotFoundError


@dataclass
class TopologyData:
    """Clean representation of loaded network topology data."""
    schema_version: Union[str, None]
    scenario_id: Union[str, None]
    description: Union[str, None]
    devices: List[Dict[str, Any]]
    links: List[Dict[str, Any]]
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return raw loaded JSON dictionary preserving all original fields."""
        return self.raw


def load_topology(file_path: Union[str, Path]) -> TopologyData:
    """
    Loads and validates a topology.json file.

    Args:
        file_path: Path to the topology.json file.

    Returns:
        TopologyData object containing raw and parsed devices/links metadata.

    Raises:
        TopologyNotFoundError: If the file does not exist.
        InvalidTopologyError: If the file contains invalid JSON or improper schema structure.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise TopologyNotFoundError(f"Topology file not found: {path}")

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        raise InvalidTopologyError(f"Could not read topology file '{path}': {exc}") from exc

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise InvalidTopologyError(
            f"Invalid JSON syntax in '{path}': {exc.msg} (line {exc.lineno}, col {exc.colno})"
        ) from exc

    if not isinstance(data, dict):
        raise InvalidTopologyError(f"Root structure in '{path}' must be a JSON object")

    devices = data.get("devices")
    if devices is not None and not isinstance(devices, list):
        raise InvalidTopologyError(f"Field 'devices' in '{path}' must be a list")

    links = data.get("links")
    if links is not None and not isinstance(links, list):
        raise InvalidTopologyError(f"Field 'links' in '{path}' must be a list")

    return TopologyData(
        schema_version=data.get("schema_version"),
        scenario_id=data.get("scenario_id"),
        description=data.get("description"),
        devices=devices if devices is not None else [],
        links=links if links is not None else [],
        raw=data,
    )
