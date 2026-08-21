# Synthetic Network Evidence Schema v1.0

## topology.json
Contains scenario ID, devices, links, interfaces, and optional degraded-link health/error counters.

## events.log
One event per line:
`timestamp device severity event/details`

## traffic.pcap
Valid classic libpcap packet capture containing normal traffic, packet loss, and TCP retransmission evidence.

## ground_truth.json
Contains injected root cause, affected/unaffected devices, timestamp, propagation, and evaluation target.
