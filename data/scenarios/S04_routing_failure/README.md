# S04 — Routing Failure

## Purpose
Synthetic routing/forwarding failure incident for the OpenHack network incident reconstruction prototype.

## Incident
At `2026-08-21T10:42:02Z`, router R1 develops an invalid forwarding entry for destination SERVER (`10.0.0.20`). The physical topology remains connected and all interfaces remain UP.

## Evidence chain
1. Before the failure, PC1 and PC2 successfully reach gateway R1 and routed traffic reaches SERVER.
2. At 10:42:02Z, R1 records a ROUTE_CHANGE for destination 10.0.0.20 and a forwarding failure.
3. After the change, PC1 and PC2 can still reach gateway R1, showing that the physical R1-SW1 path remains operational.
4. Post-failure ICMP requests for SERVER are addressed at the Ethernet layer to R1, but there are no corresponding R1-to-SERVER forwarded packets or replies.
5. The topology shows that the physical links remain UP.

## Distinguishing characteristic
This scenario must be classified as a logical routing/forwarding failure, not a physical link failure.

## Files
- `topology.json` — logical network structure and dependencies
- `traffic.pcap` — synthetic packet-level evidence
- `events.log` — synthetic time-correlated device events
- `ground_truth.json` — known injected root cause for evaluation
- `schema.md` — common evidence format copied from the S01 reference
- `MANIFEST.json` — package metadata

## Important
All evidence is synthetic and intended for testing/demo use. No production network data is represented.
