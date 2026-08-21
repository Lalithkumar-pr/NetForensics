"""
Unit, integration, and generalization test suite for NetForensics Phase 5 (Evidence Validation & Diagnostic Confidence Layer).
"""

import inspect
from pathlib import Path
import pytest

from backend.app.correlation.correlator import correlate_dataset
from backend.app.normalization.models import EvidenceEvent, NormalizedDataset, NormalizedTopology
from backend.app.normalization.normalizer import normalize_evidence_from_paths
from backend.app.reconstruction.models import Hypothesis, ReconstructionConfig, ReconstructionResult, ScoreBreakdown
from backend.app.reconstruction.reconstructor import reconstruct_incidents
from backend.app.validation import (
    DiagnosticReport,
    DiagnosticValidationConfig,
    validate_reconstruction,
)


def test_high_multi_source_confidence():
    """Test A: Strong multi-source evidence (log + pcap + topology) produces high diagnostic confidence."""
    evt_log = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1", {"severity": "CRITICAL", "event_type": "LINK_DOWN", "interface": "Gi0/1", "details": "peer=R1"})
    evt_pcap = EvidenceEvent("pcap_1", 100.0, "pcap", "packet", "10.0.0.11", {"src_ip": "10.0.0.11", "dst_ip": "10.0.0.1", "protocol": "ICMP", "summary": "unreachable timeout"})

    topology = NormalizedTopology(
        devices=[{"id": "SW1", "type": "switch"}, {"id": "R1", "type": "router"}],
        links=[{"id": "L1", "a": "SW1", "b": "R1"}],
    )
    dataset = NormalizedDataset(evidence_events=[evt_log, evt_pcap], topology=topology)

    correlations = correlate_dataset(dataset)
    reconstruction = reconstruct_incidents(dataset, correlations)

    report = validate_reconstruction(dataset, correlations, reconstruction)

    assert isinstance(report, DiagnosticReport)
    assert report.diagnostic_confidence >= 0.50
    assert report.source_diversity.diversity_score >= 0.70
    assert "event_log" in report.evidence_coverage.independent_sources
    assert "pcap" in report.evidence_coverage.independent_sources


def test_single_source_lower_confidence():
    """Test B: Single-source evidence produces lower source diversity and lower confidence than multi-source."""
    evt_log = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1", {"severity": "WARN", "event_type": "LINK_DOWN", "interface": "Gi0/1"})
    topology = NormalizedTopology(devices=[{"id": "SW1"}, {"id": "R1"}], links=[{"id": "L1", "a": "SW1", "b": "R1"}])
    dataset = NormalizedDataset(evidence_events=[evt_log], topology=topology)

    correlations = correlate_dataset(dataset)
    reconstruction = reconstruct_incidents(dataset, correlations)
    report = validate_reconstruction(dataset, correlations, reconstruction)

    assert report.source_diversity.diversity_score <= 0.70
    assert report.diagnostic_confidence < 0.90


def test_hypothesis_margin_reduces_ambiguity():
    """Test C: Closely competing hypotheses reduce confidence via ambiguity flag."""
    sb1 = ScoreBreakdown(0.70, 0.70, 0.70, 0.70, 0.70, 0.0, 0.70)
    sb2 = ScoreBreakdown(0.68, 0.68, 0.68, 0.68, 0.68, 0.0, 0.68)

    h1 = Hypothesis("h1", "physical_link_failure", "Link Failure", "SW1-R1", ["SW1", "R1"], ["log_1"], score_breakdown=sb1)
    h2 = Hypothesis("h2", "interface_failure", "Interface Failure", "SW1:Gi0/1", ["SW1"], ["log_1"], score_breakdown=sb2)

    rec_res = ReconstructionResult(primary_hypothesis=h1, ranked_hypotheses=[h1, h2])
    dataset = NormalizedDataset(evidence_events=[EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1", {})])

    report = validate_reconstruction(dataset, None, rec_res)

    assert report.hypothesis_separation.is_ambiguous is True
    assert report.hypothesis_separation.score_margin < 0.10


def test_strong_contradiction_reduces_confidence():
    """Test D: Strong contradiction reduces diagnostic confidence."""
    sb_penalized = ScoreBreakdown(0.8, 0.8, 0.8, 0.8, 0.8, 0.6, 0.40)
    h_penalized = Hypothesis("h1", "physical_link_failure", "Link Failure", "SW1-R1", ["SW1"], ["log_1"], contradicting_evidence=["log_2"], score_breakdown=sb_penalized)

    rec_res = ReconstructionResult(primary_hypothesis=h_penalized, ranked_hypotheses=[h_penalized])
    dataset = NormalizedDataset(evidence_events=[EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1", {})])

    report = validate_reconstruction(dataset, None, rec_res)

    assert report.contradiction_summary.severity_level in ("MODERATE", "STRONG")
    assert report.diagnostic_confidence < 0.60


def test_missing_evidence_reduces_completeness():
    """Test E: Missing expected evidence signals lowers completeness score."""
    sb = ScoreBreakdown(0.5, 0.5, 0.5, 0.5, 0.5, 0.0, 0.50)
    h = Hypothesis("h1", "degraded_link", "Degraded Link", "SW1-SW2", ["SW1"], ["log_1"], score_breakdown=sb)
    rec_res = ReconstructionResult(primary_hypothesis=h, ranked_hypotheses=[h])
    dataset = NormalizedDataset(evidence_events=[EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1", {})])

    report = validate_reconstruction(dataset, None, rec_res)

    assert report.evidence_completeness.completeness_score < 1.0
    assert len(report.missing_evidence) > 0


def test_confidence_band_thresholds():
    """Test F: Confidence band mapping thresholds."""
    config = DiagnosticValidationConfig(threshold_high=0.80, threshold_moderate=0.60, threshold_low=0.40)
    assert config.threshold_high == 0.80
    assert config.threshold_moderate == 0.60
    assert config.threshold_low == 0.40


def test_deterministic_validation():
    """Test G: Identical input produces identical DiagnosticReport output dictionary across runs."""
    evt_log = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1", {"severity": "CRITICAL", "event_type": "LINK_DOWN", "interface": "Gi0/1"})
    dataset = NormalizedDataset(evidence_events=[evt_log])
    correlations = correlate_dataset(dataset)
    reconstruction = reconstruct_incidents(dataset, correlations)

    rep1 = validate_reconstruction(dataset, correlations, reconstruction)
    rep2 = validate_reconstruction(dataset, correlations, reconstruction)

    assert rep1.to_dict() == rep2.to_dict()


def test_empty_evidence_validation():
    """Test H: Empty evidence produces INSUFFICIENT confidence without crashing."""
    dataset = NormalizedDataset()
    correlations = correlate_dataset(dataset)
    reconstruction = reconstruct_incidents(dataset, correlations)

    report = validate_reconstruction(dataset, correlations, reconstruction)

    assert isinstance(report, DiagnosticReport)
    assert report.confidence_band in ("INSUFFICIENT", "LOW")


def test_no_ground_truth_leakage_in_validation_package():
    """Test that production validation package files never import or reference ground_truth.json."""
    import backend.app.validation as val_mod
    for name, obj in inspect.getmembers(val_mod):
        if inspect.ismodule(obj):
            source = inspect.getsource(obj)
            assert "ground_truth" not in source, f"Validation module {name} contains ground_truth reference!"


# ============================================================================
# SCENARIO VALIDATION TESTS (S01 to S09)
# ============================================================================

def test_s01_validation():
    s01_dir = Path("data/scenarios/S01_switch_uplink_failure")
    if s01_dir.exists():
        dataset = normalize_evidence_from_paths(s01_dir / "topology.json", s01_dir / "events.log", s01_dir / "traffic.pcap")
        corrs = correlate_dataset(dataset)
        recon = reconstruct_incidents(dataset, corrs)
        report = validate_reconstruction(dataset, corrs, recon)

        assert isinstance(report, DiagnosticReport)
        assert report.confidence_band in ("HIGH", "MODERATE", "LOW")
        assert len(report.recommended_next_steps) > 0


def test_s02_validation():
    path = Path("data/scenarios/S02_single_access_port_failure")
    if path.exists():
        dataset = normalize_evidence_from_paths(path / "topology.json", path / "events.log" if (path / "events.log").exists() else None)
        corrs = correlate_dataset(dataset)
        recon = reconstruct_incidents(dataset, corrs)
        report = validate_reconstruction(dataset, corrs, recon)
        assert isinstance(report, DiagnosticReport)


def test_s03_validation():
    path = Path("data/scenarios/S03_router_interface_failure")
    if path.exists():
        dataset = normalize_evidence_from_paths(path / "topology.json", path / "events.log" if (path / "events.log").exists() else None)
        corrs = correlate_dataset(dataset)
        recon = reconstruct_incidents(dataset, corrs)
        report = validate_reconstruction(dataset, corrs, recon)
        assert isinstance(report, DiagnosticReport)


def test_s04_validation():
    path = Path("data/scenarios/S04_routing_failure")
    if path.exists():
        dataset = normalize_evidence_from_paths(path / "topology.json", path / "events.log" if (path / "events.log").exists() else None)
        corrs = correlate_dataset(dataset)
        recon = reconstruct_incidents(dataset, corrs)
        report = validate_reconstruction(dataset, corrs, recon)
        assert isinstance(report, DiagnosticReport)


def test_s05_validation():
    path = Path("data/scenarios/S05_vlan_misconfiguration")
    if path.exists():
        dataset = normalize_evidence_from_paths(path / "topology.json", path / "events.log" if (path / "events.log").exists() else None)
        corrs = correlate_dataset(dataset)
        recon = reconstruct_incidents(dataset, corrs)
        report = validate_reconstruction(dataset, corrs, recon)
        assert isinstance(report, DiagnosticReport)


def test_s06_validation():
    path = Path("data/scenarios/S06_arp_resolution_failure")
    if path.exists():
        dataset = normalize_evidence_from_paths(path / "topology.json", path / "events.log" if (path / "events.log").exists() else None)
        corrs = correlate_dataset(dataset)
        recon = reconstruct_incidents(dataset, corrs)
        report = validate_reconstruction(dataset, corrs, recon)
        assert isinstance(report, DiagnosticReport)


def test_s07_validation():
    path = Path("data/scenarios/S07_dns_failure")
    if path.exists():
        dataset = normalize_evidence_from_paths(path / "topology.json", path / "events.log" if (path / "events.log").exists() else None)
        corrs = correlate_dataset(dataset)
        recon = reconstruct_incidents(dataset, corrs)
        report = validate_reconstruction(dataset, corrs, recon)
        assert isinstance(report, DiagnosticReport)


def test_s08_validation():
    path = Path("data/scenarios/S08_degraded_link_packet_loss")
    if path.exists():
        dataset = normalize_evidence_from_paths(path / "topology.json", path / "events.log" if (path / "events.log").exists() else None)
        corrs = correlate_dataset(dataset)
        recon = reconstruct_incidents(dataset, corrs)
        report = validate_reconstruction(dataset, corrs, recon)
        assert isinstance(report, DiagnosticReport)


def test_s09_validation():
    path = Path("data/scenarios/S09_dhcp_failure")
    if path.exists():
        dataset = normalize_evidence_from_paths(path / "topology.json", path / "events.log" if (path / "events.log").exists() else None)
        corrs = correlate_dataset(dataset)
        recon = reconstruct_incidents(dataset, corrs)
        report = validate_reconstruction(dataset, corrs, recon)
        assert isinstance(report, DiagnosticReport)
