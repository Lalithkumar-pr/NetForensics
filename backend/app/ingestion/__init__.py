"""
NetForensics Ingestion Package.
Provides evidence loaders for topology configurations, event log files, and packet captures.
"""

from .exceptions import (
    EventLogError,
    EventLogNotFoundError,
    IngestionError,
    InvalidEventLogError,
    InvalidPcapError,
    InvalidTopologyError,
    PcapError,
    PcapNotFoundError,
    TopologyError,
    TopologyNotFoundError,
)
from .event_log_loader import EventLogEntry, load_events
from .pcap_loader import PacketRecord, load_pcap
from .topology_loader import TopologyData, load_topology

__all__ = [
    "load_topology",
    "TopologyData",
    "load_events",
    "EventLogEntry",
    "load_pcap",
    "PacketRecord",
    "IngestionError",
    "TopologyError",
    "TopologyNotFoundError",
    "InvalidTopologyError",
    "EventLogError",
    "EventLogNotFoundError",
    "InvalidEventLogError",
    "PcapError",
    "PcapNotFoundError",
    "InvalidPcapError",
]
