"""
Evidence coverage and source diversity analysis module for NetForensics (Phase 5).
"""

from typing import List, Optional, Set
from backend.app.normalization.models import EvidenceEvent, NormalizedDataset
from backend.app.reconstruction.models import Hypothesis
from .models import EvidenceCoverage, SourceDiversity


def evaluate_evidence_coverage(
    hypothesis: Optional[Hypothesis],
    dataset: NormalizedDataset,
    supporting_events: List[EvidenceEvent],
) -> EvidenceCoverage:
    """
    Evaluates evidence coverage breadth across evidence categories and sources.
    """
    if hypothesis is None:
        return EvidenceCoverage(
            event_count=0,
            independent_sources=[],
            has_event_log_support=False,
            has_pcap_support=False,
            has_topology_support=False,
            has_temporal_support=False,
            has_propagation_support=False,
            coverage_score=0.0,
        )

    sources: Set[str] = {evt.source for evt in supporting_events}

    sb = hypothesis.score_breakdown
    has_event_log = any(evt.source == "event_log" for evt in supporting_events) or any(evt.source == "event_log" for evt in dataset.evidence_events)
    if has_event_log:
        sources.add("event_log")

    has_pcap = any(evt.source == "pcap" for evt in supporting_events) or any(evt.source == "pcap" for evt in dataset.evidence_events)
    if has_pcap:
        sources.add("pcap")

    has_topology = (sb.topology_consistency >= 0.60) if sb else False
    if has_topology:
        sources.add("topology")

    has_temporal = (sb.temporal_consistency >= 0.50) if sb else False
    has_propagation = (sb.propagation_consistency >= 0.50) if sb else False

    # Calculate coverage score [0.0, 1.0] from dimensional presence
    dimensions = [
        has_event_log,
        has_pcap,
        has_topology,
        has_temporal,
        has_propagation,
    ]
    present_dims = sum(1 for d in dimensions if d)

    if present_dims == 0:
        coverage_score = 0.0
    elif present_dims == 1:
        coverage_score = 0.35
    elif present_dims == 2:
        coverage_score = 0.60
    elif present_dims == 3:
        coverage_score = 0.80
    elif present_dims == 4:
        coverage_score = 0.92
    else:
        coverage_score = 1.00

    return EvidenceCoverage(
        event_count=len(supporting_events),
        independent_sources=sorted(list(sources)),
        has_event_log_support=has_event_log,
        has_pcap_support=has_pcap,
        has_topology_support=has_topology,
        has_temporal_support=has_temporal,
        has_propagation_support=has_propagation,
        coverage_score=coverage_score,
    )


def evaluate_source_diversity(
    independent_sources: List[str],
) -> SourceDiversity:
    """
    Evaluates source diversity score based on independent evidence sources.
    """
    count = len(independent_sources)
    if count == 0:
        diversity_score = 0.0
    elif count == 1:
        diversity_score = 0.35
    elif count == 2:
        diversity_score = 0.70
    else:
        diversity_score = 1.00

    return SourceDiversity(
        sources_present=sorted(independent_sources),
        diversity_score=diversity_score,
    )
