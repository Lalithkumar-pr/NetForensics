"""
Integration test suite for NetForensics API layer and scenario investigation endpoints (Final Phase).
"""

import inspect
from pathlib import Path
import pytest

from backend.app.api.router import get_available_scenarios, run_investigation


def test_get_scenarios_returns_all_scenarios():
    """Test that get_available_scenarios discovers all S01-S09 scenario datasets."""
    scenarios = get_available_scenarios()
    assert len(scenarios) >= 9

    s_ids = [s["scenario_id"] for s in scenarios]
    for expected in ["S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09"]:
        assert expected in s_ids, f"Scenario {expected} missing from available scenarios list!"


def test_investigate_s01_switch_uplink_failure():
    """Test end-to-end investigation execution for S01 (Physical Link Failure)."""
    res = run_investigation("S01")
    assert res["status"] == "success"
    assert res["scenario_info"]["scenario_id"] == "S01"
    assert res["evidence_summary"]["total_events"] > 0

    primary = res["primary_hypothesis"]
    assert primary["hypothesis_type"] in ("physical_link_failure", "interface_failure")
    assert primary["score"] > 0.0

    assert "score_breakdown" in res
    assert "diagnostic_validation" in res
    assert "supporting_evidence" in res
    assert "timeline" in res
    assert "impact" in res
    assert "ranked_candidates" in res


def test_investigate_s04_routing_failure():
    """Test end-to-end investigation execution for S04 (Routing Failure)."""
    res = run_investigation("S04")
    assert res["status"] == "success"
    assert res["scenario_info"]["scenario_id"] == "S04"
    assert res["primary_hypothesis"]["score"] >= 0.0


def test_investigate_s07_dns_service_failure():
    """Test end-to-end investigation execution for S07 (DNS Service Failure)."""
    res = run_investigation("S07")
    assert res["status"] == "success"
    assert res["scenario_info"]["scenario_id"] == "S07"
    assert res["primary_hypothesis"]["hypothesis_type"] in ("service_failure", "addressing_failure")


def test_investigate_s08_degraded_link_packet_loss():
    """Test end-to-end investigation execution for S08 (Degraded Link / Packet Loss)."""
    res = run_investigation("S08")
    assert res["status"] == "success"
    assert res["scenario_info"]["scenario_id"] == "S08"
    assert res["primary_hypothesis"]["score"] >= 0.0


def test_investigate_s09_dhcp_failure():
    """Test end-to-end investigation execution for S09 (DHCP Service Failure)."""
    res = run_investigation("S09")
    assert res["status"] == "success"
    assert res["scenario_info"]["scenario_id"] == "S09"
    assert res["primary_hypothesis"]["score"] >= 0.0


def test_investigate_missing_scenario_returns_error():
    """Test robust error handling for non-existent scenario ID."""
    res = run_investigation("S99_invalid_nonexistent")
    assert res["status"] == "error"
    assert "not found" in res["error"]


def test_no_ground_truth_leakage_in_api():
    """Test that API code modules never import or reference ground_truth.json."""
    import backend.app.api.router as router_mod
    source = inspect.getsource(router_mod)
    assert "ground_truth" not in source, "API router must not reference ground_truth!"
