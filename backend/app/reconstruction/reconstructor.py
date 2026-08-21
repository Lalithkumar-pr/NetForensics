"""
Core reconstruction orchestrator for NetForensics.
Evaluates, scores, ranks root-cause hypotheses deterministically.
"""

from typing import List, Optional
from backend.app.correlation.correlator import correlate_dataset
from backend.app.correlation.models import CorrelationResult
from backend.app.normalization.models import EvidenceEvent, NormalizedDataset
from .explanations import generate_auditable_explanation
from .hypotheses import generate_candidate_hypotheses
from .models import Hypothesis, IncidentContext, ReconstructionConfig, ReconstructionResult
from .scoring import evaluate_hypothesis_score


def match_supporting_events(
    hypothesis: Hypothesis,
    events: List[EvidenceEvent],
) -> List[EvidenceEvent]:
    """
    Finds evidence events supporting a hypothesis based on target entity and attributes.
    """
    supporting: List[EvidenceEvent] = []
    target = hypothesis.target_entity or ""
    target_clean = target.split(":")[0].split("-")[0]
    involved = set(hypothesis.involved_entities)

    for evt in events:
        entity = evt.entity or ""
        details = (evt.attributes.get("details") or "").lower()
        summary = (evt.attributes.get("summary") or "").lower()
        evt_type = (evt.attributes.get("event_type") or "").upper()
        iface = evt.attributes.get("interface")

        is_match = False

        # Entity / Device match
        if entity and (entity == target_clean or entity in involved):
            is_match = True

        # Link match (e.g. SW1-R1)
        if "-" in target:
            node_a, node_b = target.split("-")[0], target.split("-")[1]
            if entity in (node_a, node_b) or node_a in details or node_b in details:
                is_match = True

        # Interface match (e.g. SW1:Gi0/1)
        if ":" in target:
            dev_part, iface_part = target.split(":", 1)
            if entity == dev_part and iface == iface_part:
                is_match = True

        # Service / Port match (e.g. SERVER:DNS or DHCP)
        if hypothesis.hypothesis_type in ("service_failure", "addressing_failure"):
            if "dns" in summary or "dns" in details or "dhcp" in summary or "dhcp" in details or "port 53" in summary or "port 67" in summary:
                is_match = True

        if is_match:
            supporting.append(evt)

    return supporting


def reconstruct_incidents(
    dataset: NormalizedDataset,
    correlation_result: Optional[CorrelationResult] = None,
    config: Optional[ReconstructionConfig] = None,
) -> ReconstructionResult:
    """
    Deterministically reconstructs incident candidates and produces a ranked list of hypotheses.

    Args:
        dataset: NormalizedDataset containing evidence events and topology.
        correlation_result: Optional CorrelationResult. Generated via Phase 3 if None.
        config: Optional ReconstructionConfig. Uses default weights if None.

    Returns:
        ReconstructionResult with primary_hypothesis and ranked_hypotheses.
    """
    if config is None:
        config = ReconstructionConfig()

    if correlation_result is None:
        correlation_result = correlate_dataset(dataset)

    context = IncidentContext(dataset=dataset, correlation_result=correlation_result)
    candidates = generate_candidate_hypotheses(context)

    evaluated_hypotheses: List[Hypothesis] = []

    for hyp in candidates:
        supp_events = match_supporting_events(hyp, dataset.evidence_events)
        hyp.supporting_evidence = [e.id for e in supp_events]

        score_breakdown = evaluate_hypothesis_score(hyp, dataset, supp_events, config)
        hyp.score_breakdown = score_breakdown

        evaluated_hypotheses.append(hyp)

    # Sort descending by final_score, breaking ties deterministically by hypothesis ID
    ranked = sorted(
        evaluated_hypotheses,
        key=lambda h: (h.score_breakdown.final_score if h.score_breakdown else 0.0, h.id),
        reverse=True,
    )

    # Determine confidence levels based on ranking gaps
    for idx, hyp in enumerate(ranked):
        sb = hyp.score_breakdown
        score = sb.final_score if sb else 0.0
        gap = (score - ranked[idx + 1].score_breakdown.final_score) if (idx + 1 < len(ranked) and ranked[idx + 1].score_breakdown) else score

        if score >= 0.70 and gap >= 0.15:
            hyp.confidence_level = "HIGH"
        elif score >= 0.45:
            hyp.confidence_level = "MEDIUM"
        else:
            hyp.confidence_level = "LOW"

        # Generate auditable explanation string
        supp_events = match_supporting_events(hyp, dataset.evidence_events)
        hyp.explanation = generate_auditable_explanation(hyp, dataset, supp_events)

    primary = ranked[0] if ranked else None

    return ReconstructionResult(
        primary_hypothesis=primary,
        ranked_hypotheses=ranked,
        config=config,
    )
