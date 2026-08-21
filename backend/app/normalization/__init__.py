"""
NetForensics Normalization Package.
Converts Phase 1 ingestion outputs into structured internal representations.
"""

from .models import EvidenceEvent, NormalizedDataset, NormalizedTopology
from .normalizer import (
    normalize_dataset,
    normalize_event_log_entry,
    normalize_evidence_from_paths,
    normalize_packet_record,
    normalize_topology,
)

__all__ = [
    "EvidenceEvent",
    "NormalizedTopology",
    "NormalizedDataset",
    "normalize_event_log_entry",
    "normalize_packet_record",
    "normalize_topology",
    "normalize_dataset",
    "normalize_evidence_from_paths",
]
