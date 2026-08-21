# Synthetic Network Evidence Schema v1.0

## topology.json
Contains:
- `scenario_id`
- `devices[]`
- `links[]`
- device IDs, types, IPs and interface/link relationships

For scenarios involving VLAN configuration, relevant VLAN state/change metadata may be included on the affected link without changing the core schema structure.

## events.log
One event per line:
`timestamp device severity event/details`

Timestamps use UTC ISO-8601 format.

## traffic.pcap
Valid libpcap packet capture.
For S05 it contains:
- normal ICMP request/reply traffic before the VLAN change
- post-change ARP requests from PC1 with no gateway resolution
- continued successful ICMP request/reply traffic from PC2

## ground_truth.json
Contains:
- injected root cause
- affected/unaffected devices
- failure/configuration timestamp
- expected propagation
- evaluation target

## Naming rules
- Device IDs: `R1`, `SW1`, `SW2`, `PC1`, `PC2`, `SERVER`
- IP addresses: `10.0.0.0/24`
- Timestamps: UTC ISO-8601 with `Z`
