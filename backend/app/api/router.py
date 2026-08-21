"""
API Router implementation for NetForensics (Final Phase).
Exposes endpoints for scenario discovery and end-to-end incident investigation execution.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from backend.app.correlation.correlator import correlate_dataset
from backend.app.normalization.normalizer import normalize_evidence_from_paths
from backend.app.reconstruction.reconstructor import reconstruct_incidents
from backend.app.validation.validator import validate_reconstruction


SCENARIO_TITLES: Dict[str, str] = {
    "S01": "S01 - Switch Uplink Failure",
    "S02": "S02 - Single Access Port Failure",
    "S03": "S03 - Router Interface Failure",
    "S04": "S04 - Routing Failure",
    "S05": "S05 - VLAN Misconfiguration",
    "S06": "S06 - ARP Resolution Failure",
    "S07": "S07 - DNS Service Failure",
    "S08": "S08 - Degraded Link / Packet Loss",
    "S09": "S09 - DHCP Service Failure",
}


def get_available_scenarios(
    scenarios_base_dir: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """
    Scans the data/scenarios directory and returns a sorted list of available scenario metadata.
    """
    base = Path(scenarios_base_dir) if scenarios_base_dir else Path("data/scenarios")
    scenarios: List[Dict[str, Any]] = []

    if not base.exists() or not base.is_dir():
        return scenarios

    for s_dir in sorted(base.iterdir(), key=lambda p: p.name):
        if s_dir.is_dir() and (s_dir / "topology.json").exists():
            folder_name = s_dir.name
            s_id = folder_name.split("_")[0] if "_" in folder_name else folder_name

            title = SCENARIO_TITLES.get(s_id, f"{s_id} - {folder_name.replace('_', ' ').title()}")
            description = f"Network incident scenario dataset ({folder_name})"

            topo_file = s_dir / "topology.json"
            try:
                import json
                topo_data = json.loads(topo_file.read_text(encoding="utf-8"))
                if topo_data.get("description"):
                    description = topo_data["description"]
            except Exception:
                pass

            scenarios.append({
                "scenario_id": s_id,
                "folder_name": folder_name,
                "title": title,
                "description": description,
                "has_pcap": (s_dir / "traffic.pcap").exists(),
                "has_events": (s_dir / "events.log").exists(),
            })

    return scenarios


def resolve_scenario_path(scenario_id_or_name: str, base_dir: Path) -> Optional[Path]:
    """
    Resolves scenario identifier (e.g. 'S01' or 'S01_switch_uplink_failure') to folder path.
    """
    clean_id = scenario_id_or_name.strip()

    # Direct folder match
    direct = base_dir / clean_id
    if direct.exists() and direct.is_dir():
        return direct

    # Prefix match
    for s_dir in base_dir.iterdir():
        if s_dir.is_dir() and (s_dir.name == clean_id or s_dir.name.startswith(f"{clean_id}_")):
            return s_dir

    return None


def run_investigation(
    scenario_id: str,
    scenarios_base_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Executes the end-to-end deterministic forensic investigation pipeline for a scenario.

    Pipeline:
      Phase 1 Ingestion + Phase 2 Normalization -> Phase 3 Correlation -> Phase 4 Reconstruction -> Phase 5 Validation

    Returns:
      Comprehensive JSON-serializable investigation result dictionary.
    """
    base = Path(scenarios_base_dir) if scenarios_base_dir else Path("data/scenarios")
    scenario_path = resolve_scenario_path(scenario_id, base)

    if not scenario_path or not scenario_path.exists():
        return {
            "status": "error",
            "error": f"Scenario '{scenario_id}' not found in data/scenarios.",
            "available_scenarios": [s["scenario_id"] for s in get_available_scenarios(base)],
        }

    try:
        # Phase 1 + Phase 2: Ingestion & Normalization
        topo_path = scenario_path / "topology.json"
        events_path = scenario_path / "events.log" if (scenario_path / "events.log").exists() else None
        pcap_path = scenario_path / "traffic.pcap" if (scenario_path / "traffic.pcap").exists() else None

        dataset = normalize_evidence_from_paths(
            topology_path=topo_path if topo_path.exists() else None,
            events_path=events_path,
            pcap_path=pcap_path,
        )

        # Phase 3: Correlation
        correlations = correlate_dataset(dataset)

        # Phase 4: Reconstruction
        reconstruction = reconstruct_incidents(dataset, correlations)

        # Phase 5: Validation
        validation = validate_reconstruction(dataset, correlations, reconstruction)

        # Build investigation payload
        primary = reconstruction.primary_hypothesis
        sb = primary.score_breakdown if primary else None

        # Build events lookup for supporting/contradicting evidence details
        events_map = {e.id: e for e in dataset.evidence_events}

        supporting_events_list: List[Dict[str, Any]] = []
        if primary and primary.supporting_evidence:
            for eid in primary.supporting_evidence:
                if eid in events_map:
                    evt = events_map[eid]
                    summary = evt.attributes.get("details") or evt.attributes.get("summary") or evt.attributes.get("event_type") or ""
                    supporting_events_list.append({
                        "id": evt.id,
                        "timestamp": str(evt.timestamp),
                        "source": evt.source,
                        "category": evt.category,
                        "entity": evt.entity or "N/A",
                        "summary": summary,
                    })

        contradicting_events_list: List[Dict[str, Any]] = []
        if primary and primary.contradicting_evidence:
            for eid in primary.contradicting_evidence:
                if eid in events_map:
                    evt = events_map[eid]
                    summary = evt.attributes.get("details") or evt.attributes.get("summary") or evt.attributes.get("event_type") or ""
                    contradicting_events_list.append({
                        "id": evt.id,
                        "timestamp": str(evt.timestamp),
                        "source": evt.source,
                        "category": evt.category,
                        "entity": evt.entity or "N/A",
                        "summary": summary,
                    })

        # Timeline list
        timeline: List[Dict[str, Any]] = []
        for evt in dataset.evidence_events:
            summary = evt.attributes.get("details") or evt.attributes.get("summary") or evt.attributes.get("event_type") or ""
            timeline.append({
                "id": evt.id,
                "timestamp": str(evt.timestamp),
                "source": evt.source,
                "category": evt.category,
                "entity": evt.entity or "N/A",
                "summary": summary,
            })

        # Ranked alternative candidates
        ranked_candidates: List[Dict[str, Any]] = []
        for idx, h in enumerate(reconstruction.ranked_hypotheses, 1):
            h_score = h.score_breakdown.final_score if h.score_breakdown else 0.0
            ranked_candidates.append({
                "rank": idx,
                "id": h.id,
                "hypothesis_type": h.hypothesis_type,
                "title": h.title,
                "target_entity": str(h.target_entity or "N/A"),
                "score": round(h_score, 4),
                "confidence": h.confidence_level,
                "explanation": h.explanation,
            })

        # Affected / Unaffected propagation entities
        affected_entities = list({e.entity for e in dataset.evidence_events if e.entity and ("DOWN" in str(e.attributes.get("event_type", "")) or "timeout" in str(e.attributes.get("details", "")).lower())})
        all_devices = [d.get("id") for d in dataset.topology.devices if d.get("id")]
        unaffected_entities = [d for d in all_devices if d not in affected_entities]

        folder_name = scenario_path.name
        s_id = folder_name.split("_")[0] if "_" in folder_name else folder_name
        title = SCENARIO_TITLES.get(s_id, f"{s_id} - {folder_name.replace('_', ' ').title()}")

        return {
            "status": "success",
            "scenario_info": {
                "scenario_id": s_id,
                "folder_name": folder_name,
                "title": title,
            },
            "evidence_summary": {
                "total_events": len(dataset.evidence_events),
                "log_events_count": sum(1 for e in dataset.evidence_events if e.source == "event_log"),
                "pcap_packets_count": sum(1 for e in dataset.evidence_events if e.source == "pcap"),
                "devices_count": len(dataset.topology.devices),
                "links_count": len(dataset.topology.links),
            },
            "correlations_summary": {
                "total_relationships": len(correlations.relationships),
                "relationships": [
                    {
                        "source_event_id": rel.source_event_id,
                        "target_event_id": rel.target_event_id,
                        "relationship_types": rel.relationship_types,
                        "explanation": rel.explanation,
                    }
                    for rel in correlations.relationships[:10]
                ],
            },
            "primary_hypothesis": {
                "id": primary.id if primary else "none",
                "hypothesis_type": primary.hypothesis_type if primary else "none",
                "title": primary.title if primary else "No Root Cause Found",
                "target_entity": str(primary.target_entity if primary else "N/A"),
                "score": round(sb.final_score, 4) if sb else 0.0,
                "confidence_level": primary.confidence_level if primary else "LOW",
                "explanation": primary.explanation if primary else "Insufficient evidence.",
            },
            "score_breakdown": {
                "evidence_support": round(sb.evidence_support, 4) if sb else 0.0,
                "temporal_consistency": round(sb.temporal_consistency, 4) if sb else 0.0,
                "topology_consistency": round(sb.topology_consistency, 4) if sb else 0.0,
                "propagation_consistency": round(sb.propagation_consistency, 4) if sb else 0.0,
                "specificity": round(sb.specificity, 4) if sb else 0.0,
                "contradiction_penalty": round(sb.contradiction_penalty, 4) if sb else 0.0,
                "final_score": round(sb.final_score, 4) if sb else 0.0,
            },
            "diagnostic_validation": validation.to_dict(),
            "supporting_evidence": supporting_events_list,
            "contradicting_evidence": contradicting_events_list,
            "timeline": timeline,
            "impact": {
                "affected_entities": sorted(affected_entities),
                "unaffected_entities": sorted(unaffected_entities),
            },
            "ranked_candidates": ranked_candidates,
            "recommended_next_steps": [rec.to_dict() for rec in validation.recommended_next_steps],
            "forensic_traceability": {
                "supporting_event_ids": sorted(primary.supporting_evidence) if primary else [],
                "contradicting_event_ids": sorted(validation.contradiction_summary.contradicting_event_ids),
            },
        }

    except Exception as exc:
        return {
            "status": "error",
            "error": f"Failed to execute investigation for scenario '{scenario_id}': {str(exc)}",
        }
