"""
Deterministic correlation rules for the NetForensics evidence correlation layer.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, Union

from backend.app.normalization.models import EvidenceEvent, NormalizedTopology
from .models import CorrelationConfig


def parse_timestamp(ts: Union[str, float, int, None]) -> Optional[float]:
    """
    Parses ISO-8601 string or numeric timestamp into UTC epoch seconds float.
    """
    if ts is None:
        return None
    if isinstance(ts, (float, int)):
        return float(ts)
    if isinstance(ts, str):
        clean_ts = ts.rstrip("Z")
        if clean_ts != ts:
            try:
                dt = datetime.fromisoformat(clean_ts).replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                pass
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    return None


def check_temporal_rule(
    event_a: EvidenceEvent,
    event_b: EvidenceEvent,
    config: CorrelationConfig,
) -> Tuple[bool, Optional[float], str]:
    """
    Evaluates whether two events occurred within the configured temporal window.
    """
    t_a = parse_timestamp(event_a.timestamp)
    t_b = parse_timestamp(event_b.timestamp)

    if t_a is None or t_b is None:
        return False, None, ""

    delta = abs(t_a - t_b)
    if delta <= config.temporal_window_seconds:
        explanation = (
            f"Events occurred within configured temporal window "
            f"({delta:.2f}s <= {config.temporal_window_seconds:.2f}s)"
        )
        return True, delta, explanation

    return False, delta, ""


def check_entity_rule(
    event_a: EvidenceEvent,
    event_b: EvidenceEvent,
) -> Tuple[bool, str]:
    """
    Evaluates whether two events reference the same device, interface, or IP entity.
    """
    # 1. Direct entity match
    if event_a.entity and event_b.entity and event_a.entity == event_b.entity:
        return True, f"Both evidence records reference entity '{event_a.entity}'"

    # 2. Interface match on the same device
    if event_a.entity and event_b.entity and event_a.entity == event_b.entity:
        iface_a = event_a.attributes.get("interface")
        iface_b = event_b.attributes.get("interface")
        if iface_a and iface_b and iface_a == iface_b:
            return True, f"Both evidence records reference interface '{iface_a}' on '{event_a.entity}'"

    # 3. Entity to IP attribute match
    src_ip_b = event_b.attributes.get("src_ip")
    dst_ip_b = event_b.attributes.get("dst_ip")
    if event_a.entity and (event_a.entity == src_ip_b or event_a.entity == dst_ip_b):
        return True, f"Entity '{event_a.entity}' matches IP endpoint in second record"

    src_ip_a = event_a.attributes.get("src_ip")
    dst_ip_a = event_a.attributes.get("dst_ip")
    if event_b.entity and (event_b.entity == src_ip_a or event_b.entity == dst_ip_a):
        return True, f"Entity '{event_b.entity}' matches IP endpoint in first record"

    return False, ""


def check_topology_rule(
    event_a: EvidenceEvent,
    event_b: EvidenceEvent,
    topology: NormalizedTopology,
) -> Tuple[bool, str]:
    """
    Evaluates whether two events involve topologically adjacent network entities.
    """
    if not event_a.entity or not event_b.entity:
        return False, ""

    entity_a = event_a.entity
    entity_b = event_b.entity

    if entity_a == entity_b:
        return False, ""

    for link in topology.links:
        link_id = link.get("id", "link")
        node_a = link.get("a")
        node_b = link.get("b")

        if (node_a == entity_a and node_b == entity_b) or (node_b == entity_a and node_a == entity_b):
            a_iface = link.get("a_interface")
            b_iface = link.get("b_interface")
            iface_str = f" ({a_iface} <-> {b_iface})" if a_iface and b_iface else ""
            return True, f"Entities '{entity_a}' and '{entity_b}' are connected by topology link '{link_id}'{iface_str}"

    return False, ""


def check_network_flow_rule(
    event_a: EvidenceEvent,
    event_b: EvidenceEvent,
) -> Tuple[bool, str]:
    """
    Evaluates network flow matching between packet observations and event log messages.
    """
    # 1. Packet to packet flow match
    if event_a.source == "pcap" and event_b.source == "pcap":
        src_a, dst_a = event_a.attributes.get("src_ip"), event_a.attributes.get("dst_ip")
        src_b, dst_b = event_b.attributes.get("src_ip"), event_b.attributes.get("dst_ip")
        if src_a and dst_a and src_b and dst_b:
            if (src_a == src_b and dst_a == dst_b) or (src_a == dst_b and dst_a == src_b):
                return True, f"Matching packet flow endpoints between {src_a} and {dst_a}"

    # 2. Packet to Log detail match
    pcap_evt, log_evt = (
        (event_a, event_b) if event_a.source == "pcap" and event_b.source == "event_log"
        else ((event_b, event_a) if event_b.source == "pcap" and event_a.source == "event_log" else (None, None))
    )

    if pcap_evt and log_evt:
        src_ip = pcap_evt.attributes.get("src_ip")
        dst_ip = pcap_evt.attributes.get("dst_ip")
        details = log_evt.attributes.get("details", "") or ""

        if dst_ip and f"destination={dst_ip}" in details:
            return True, f"Packet destination IP '{dst_ip}' matches log observation details ('{details}')"
        if dst_ip and f"gateway={dst_ip}" in details:
            return True, f"Packet destination IP '{dst_ip}' matches log gateway details ('{details}')"
        if src_ip and f"gateway={src_ip}" in details:
            return True, f"Packet source IP '{src_ip}' matches log gateway details ('{details}')"

    return False, ""
