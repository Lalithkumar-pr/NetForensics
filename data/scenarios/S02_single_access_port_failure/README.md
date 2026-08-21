# S02 — Single Access-Port Failure

## Purpose
Synthetic network incident testing isolation of a single host access-port failure.

## Incident
The SW1 access port Gi0/2 connected to PC1 eth0 fails at `2026-08-21T10:42:02Z`.

## Evidence chain
1. Before the failure, PC1 and PC2 successfully reach gateway R1.
2. At 10:42:02Z, SW1 Gi0/2 and PC1 eth0 report LINK_DOWN.
3. After the failure, PC1 sends ICMP requests toward the gateway but receives no replies.
4. PC2 continues successful gateway ICMP communication after the failure.
5. The topology shows that only PC1 depends on the failed SW1 Gi0/2 access link.

## Files
- `topology.json` — logical network structure and dependencies
- `traffic.pcap` — synthetic packet-level evidence
- `events.log` — synthetic time-correlated device events
- `ground_truth.json` — known injected root cause for evaluation
- `schema.md` — common evidence format
- `MANIFEST.json` — package metadata

## Important
All evidence is synthetic and intended for testing/demo use. No production network data is represented.
