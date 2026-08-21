# S05 — VLAN Misconfiguration

## Purpose
Synthetic incident testing whether network failure reconstruction can distinguish a VLAN/configuration failure from a physical link failure.

## Incident
SW1 access interface Gi0/2, connected to PC1 eth0, is changed from VLAN 10 to VLAN 20 at `2026-08-21T10:42:02Z`. The physical link remains up.

## Evidence chain
1. Before the incident, PC1 and PC2 successfully reach gateway R1.
2. At 10:42:02Z, SW1 Gi0/2 changes from VLAN 10 to VLAN 20.
3. PC1 subsequently sends ARP requests for 10.0.0.1 without receiving a reply and loses gateway connectivity.
4. PC2 continues successful ICMP connectivity through the same switch and gateway.
5. The topology identifies PC1's dependency on SW1 Gi0/2 and records the VLAN configuration change without marking the link down.

## Files
- `topology.json` — logical network structure, dependencies and VLAN configuration
- `traffic.pcap` — synthetic packet-level evidence
- `events.log` — synthetic time-correlated device events
- `ground_truth.json` — known injected root cause for evaluation
- `schema.md` — common evidence format
- `MANIFEST.json` — package metadata

## Important
All evidence is synthetic and intended for testing/demo use. No production network data is represented.
