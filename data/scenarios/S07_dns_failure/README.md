# S07 — DNS Failure

## Purpose
Synthetic DNS service failure scenario for the OpenHack network incident reconstruction prototype.

## Incident
The DNS service hosted on SERVER becomes unavailable at `2026-08-21T10:42:02Z`.

## Evidence chain
1. Before the failure, PC1 and PC2 successfully resolve `server.example.local` and can reach SERVER directly by IP address.
2. At 10:42:02Z, SERVER reports `DNS_SERVICE_DOWN` on UDP port 53.
3. After the failure, PC1 and PC2 send DNS queries but receive no DNS responses.
4. Direct IP connectivity from PC1 and PC2 to `10.0.0.20` continues to succeed.
5. The topology shows that the physical network path to SERVER remains operational.

## Files
- `topology.json` — logical network structure and dependencies
- `traffic.pcap` — synthetic packet-level evidence
- `events.log` — synthetic time-correlated device events
- `ground_truth.json` — known injected root cause for evaluation
- `schema.md` — common evidence format
- `MANIFEST.json` — package metadata

## Important
All evidence is synthetic and intended for testing/demo use. No production network data is represented.
