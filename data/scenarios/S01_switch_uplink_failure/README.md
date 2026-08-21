# S01 — Switch Uplink Failure

## Purpose
Reference/gold-standard synthetic incident for the OpenHack network incident reconstruction prototype.

## Incident
The uplink between switch SW1 and gateway router R1 fails at `2026-08-21T10:42:02Z`.

## Evidence chain
1. Before the failure, PC1 and PC2 successfully reach gateway R1.
2. At 10:42:02Z, SW1 Gi0/1 and R1 Gi0/0 report LINK_DOWN.
3. After the failure, PC1 and PC2 send ICMP requests toward the gateway but receive no replies.
4. The topology shows that both hosts depend on the SW1-R1 uplink for gateway connectivity.

## Files
- `topology.json` — logical network structure and dependencies
- `traffic.pcap` — synthetic packet-level evidence
- `events.log` — synthetic time-correlated device events
- `ground_truth.json` — known injected root cause for evaluation
- `schema.md` — common evidence format
- `MANIFEST.json` — package metadata

## Important
All evidence is synthetic and intended for testing/demo use. No production network data is represented.
