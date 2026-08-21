# S03 — Router Interface Failure

## Purpose
Synthetic network incident testing isolation of a gateway router interface failure affecting multiple downstream hosts.

## Incident
The R1 router interface Gi0/0 connected to SW1 Gi0/1 fails at `2026-08-21T10:42:02Z`.

## Evidence chain
1. Before the failure, PC1 and PC2 successfully reach gateway R1.
2. At 10:42:02Z, R1 Gi0/0 and SW1 Gi0/1 report LINK_DOWN.
3. After the failure, PC1 and PC2 send ICMP requests toward the gateway but receive no replies.
4. The downstream SW1-SW2-SERVER switching infrastructure remains physically present.
5. The topology shows that both PC1 and PC2 depend on the R1-SW1 connection for gateway connectivity.

## Files
- `topology.json` — logical network structure and dependencies
- `traffic.pcap` — synthetic packet-level evidence
- `events.log` — synthetic time-correlated device events
- `ground_truth.json` — known injected root cause for evaluation
- `schema.md` — common evidence format
- `MANIFEST.json` — package metadata

## Important
All evidence is synthetic and intended for testing/demo use. No production network data is represented.
