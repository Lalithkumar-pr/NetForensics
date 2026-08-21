# Synthetic Network Evidence Schema v1.0

## topology.json
Contains:
- `scenario_id`
- `devices[]`
- `links[]`
- device IDs, types, IPs and interface/link relationships

## events.log
One event per line:
`timestamp device severity event/details`

Timestamps use UTC ISO-8601 format.

## traffic.pcap
Valid libpcap packet capture.
For S01 it contains:
- normal ICMP request/reply traffic before failure
- post-failure ICMP requests with no replies

## ground_truth.json
Contains:
- injected root cause
- affected/unaffected devices
- failure timestamp
- expected propagation
- evaluation target

## Naming rules
- Device IDs: `R1`, `SW1`, `SW2`, `PC1`, `PC2`, `SERVER`
- IP addresses: `10.0.0.0/24`
- Timestamps: UTC ISO-8601 with `Z`
