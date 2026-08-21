# S06 — ARP Resolution Failure

## Purpose
Synthetic network incident testing whether the reconstruction engine can distinguish ARP resolution failure from a physical link failure.

## Incident
PC1 is unable to resolve the MAC address of gateway R1 (`10.0.0.1`) beginning at `2026-08-21T10:42:02Z`.

No physical link goes down. The topology remains operational.

## Evidence chain
1. Before the incident, PC1 successfully resolves the gateway MAC address and reaches R1 using ICMP.
2. PC2 independently resolves the same gateway and continues normal ICMP connectivity.
3. At 10:42:02Z, PC1 begins an ARP resolution failure for `10.0.0.1`.
4. The PCAP contains repeated broadcast ARP requests from PC1 with no corresponding ARP reply.
5. PC1 therefore cannot send normal gateway traffic, while PC2 continues successfully.
6. The topology shows the PC1 access path remains physically connected, so the evidence points to ARP resolution rather than a link-down condition.

## Files
- `topology.json` — logical network structure and dependencies
- `traffic.pcap` — synthetic packet-level ARP/ICMP evidence
- `events.log` — synthetic time-correlated device events
- `ground_truth.json` — known injected root cause for evaluation
- `schema.md` — common evidence format from the S01 reference
- `MANIFEST.json` — package metadata

## Important
All evidence is synthetic and intended for testing/demo use. No production network data is represented.
