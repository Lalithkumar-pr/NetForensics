"""
Generic failure signature definitions for the NetForensics reconstruction engine.
"""

from typing import Dict
from .models import FailureSignature

# Catalog of generic failure signatures
FAILURE_SIGNATURE_CATALOG: Dict[str, FailureSignature] = {
    "physical_link_failure": FailureSignature(
        type="physical_link_failure",
        description="Physical link or transceiver failure between connected network devices.",
        supporting_categories=["link_state"],
        contradicting_categories=["packet_traffic_healthy"],
        expected_propagation="Loss of physical connectivity affecting all dependent downstream nodes.",
    ),
    "interface_failure": FailureSignature(
        type="interface_failure",
        description="Logical or hardware interface failure on a specific router or switch port.",
        supporting_categories=["link_state", "system_event"],
        contradicting_categories=["packet_traffic_healthy"],
        expected_propagation="Loss of interface state affecting traffic routed or switched through that interface.",
    ),
    "degraded_link": FailureSignature(
        type="degraded_link",
        description="Physical/logical link operating with high packet loss, CRC errors, or input drops.",
        supporting_categories=["packet_loss", "link_error", "retransmission"],
        contradicting_categories=["link_down"],
        expected_propagation="Intermittent packet loss and degraded throughput across the affected link.",
    ),
    "routing_failure": FailureSignature(
        type="routing_failure",
        description="Routing protocol adjacency loss, route drop, or forwarding table misconfiguration.",
        supporting_categories=["routing_event", "connectivity"],
        contradicting_categories=["physical_link_down"],
        expected_propagation="Traffic reaches router but fails to be forwarded to destination subnet.",
    ),
    "vlan_misconfiguration": FailureSignature(
        type="vlan_misconfiguration",
        description="VLAN tag mismatch or unauthorized VLAN assignment on switch access/trunk port.",
        supporting_categories=["vlan_event", "connectivity"],
        contradicting_categories=["physical_link_down"],
        expected_propagation="Broadcast/multicast isolation preventing gateway ARP or IP reachability.",
    ),
    "arp_resolution_failure": FailureSignature(
        type="arp_resolution_failure",
        description="Inability to resolve target IP address to MAC address via ARP protocol.",
        supporting_categories=["arp_event", "connectivity"],
        contradicting_categories=["physical_link_down"],
        expected_propagation="ARP requests broadcast repeatedly with no response from gateway/destination.",
    ),
    "service_failure": FailureSignature(
        type="service_failure",
        description="Application or network protocol service failure (e.g., DNS, HTTP, NTP).",
        supporting_categories=["service_event", "connectivity"],
        contradicting_categories=["physical_link_down"],
        expected_propagation="Service queries receive no response while direct IP ping connectivity remains healthy.",
    ),
    "addressing_failure": FailureSignature(
        type="addressing_failure",
        description="DHCP server unavailability or IP address allocation/lease renewal failure.",
        supporting_categories=["dhcp_event", "addressing_event"],
        contradicting_categories=["physical_link_down"],
        expected_propagation="Host fails to acquire IP address or gateway configuration.",
    ),
    "endpoint_failure": FailureSignature(
        type="endpoint_failure",
        description="Local host, NIC, or software configuration issue isolated to a single end device.",
        supporting_categories=["connectivity", "system_event"],
        contradicting_categories=["widespread_network_outage"],
        expected_propagation="Single endpoint loses connectivity while neighboring infrastructure and hosts remain operational.",
    ),
}
