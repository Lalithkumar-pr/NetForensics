"""
Custom exception classes for the NetForensics evidence ingestion layer.
"""

class IngestionError(Exception):
    """Base exception for all ingestion errors."""
    pass


class TopologyError(IngestionError):
    """Base exception for topology loading errors."""
    pass


class TopologyNotFoundError(TopologyError, FileNotFoundError):
    """Raised when topology.json file is missing."""
    pass


class InvalidTopologyError(TopologyError, ValueError):
    """Raised when topology.json is malformed or invalid."""
    pass


class EventLogError(IngestionError):
    """Base exception for event log loading errors."""
    pass


class EventLogNotFoundError(EventLogError, FileNotFoundError):
    """Raised when events.log file is missing."""
    pass


class InvalidEventLogError(EventLogError, ValueError):
    """Raised when events.log is unreadable or malformed."""
    pass


class PcapError(IngestionError):
    """Base exception for PCAP loading errors."""
    pass


class PcapNotFoundError(PcapError, FileNotFoundError):
    """Raised when traffic.pcap file is missing."""
    pass


class InvalidPcapError(PcapError, ValueError):
    """Raised when traffic.pcap file is unreadable or corrupted."""
    pass
