"""
Auditable explanation generator for NetForensics reconstruction engine.
Produces human-readable explanations traceable to evidence event IDs without LLM assistance.
"""

from typing import List
from backend.app.normalization.models import EvidenceEvent, NormalizedDataset
from .models import Hypothesis, ScoreBreakdown


def generate_auditable_explanation(
    hypothesis: Hypothesis,
    dataset: NormalizedDataset,
    supporting_events: List[EvidenceEvent],
) -> str:
    """
    Generates a clear, auditable explanation string for a hypothesis based on scored evidence.
    """
    sb = hypothesis.score_breakdown
    final_score = sb.final_score if sb else 0.0
    conf = hypothesis.confidence_level

    lines: List[str] = [
        f"Hypothesis '{hypothesis.title}' [{hypothesis.hypothesis_type}] evaluated with score {final_score:.4f} (Confidence: {conf}).",
        f"Primary Target Entity: {hypothesis.target_entity or 'Unspecified'}",
    ]

    # 1. Supporting evidence
    if supporting_events:
        lines.append("Supporting Evidence Events:")
        for evt in supporting_events[:5]:
            ts_str = f" at {evt.timestamp}" if evt.timestamp else ""
            iface_str = f" ({evt.attributes.get('interface')})" if evt.attributes.get('interface') else ""
            details = evt.attributes.get('details') or evt.attributes.get('summary') or ""
            lines.append(f"  - [{evt.id}] {evt.source} ({evt.category}): {evt.entity}{iface_str} {evt.attributes.get('event_type') or ''} {details}{ts_str}".strip())
    else:
        lines.append("Supporting Evidence: None explicitly matched.")

    # 2. Score Component Breakdown
    if sb:
        lines.append("Score Component Breakdown:")
        lines.append(f"  - Evidence Support: {sb.evidence_support:.2f} (Weight: 0.30)")
        lines.append(f"  - Temporal Consistency: {sb.temporal_consistency:.2f} (Weight: 0.15)")
        lines.append(f"  - Topology Consistency: {sb.topology_consistency:.2f} (Weight: 0.20)")
        lines.append(f"  - Propagation Consistency: {sb.propagation_consistency:.2f} (Weight: 0.25)")
        lines.append(f"  - Specificity: {sb.specificity:.2f} (Weight: 0.10)")
        lines.append(f"  - Contradiction Penalty: -{sb.contradiction_penalty:.2f}")

    # 3. Contradictions
    if hypothesis.contradicting_evidence:
        lines.append(f"Contradicting Evidence IDs: {', '.join(hypothesis.contradicting_evidence)}")
    else:
        lines.append("Contradictions: None detected.")

    return "\n".join(lines)
