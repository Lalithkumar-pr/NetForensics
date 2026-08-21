# S08 — Degraded Link / Packet Loss

## Purpose
Synthetic incident for testing whether network reconstruction identifies a degraded link rather than a physical link failure.

## Incident
The SW1-to-SW2 link (`SW1 Gi0/4 ↔ SW2 Gi0/1`) becomes degraded at `2026-08-21T10:42:02Z`.

The link remains **UP**, while CRC/input errors and packet loss increase.

## Evidence chain
1. PC1 and PC2 have successful connectivity before degradation.
2. SW1/SW2 report the link as degraded at 10:42:02Z.
3. PC1 experiences intermittent ICMP loss and TCP retransmissions.
4. PC2 continues successful ICMP traffic.
5. The topology records the affected link as `status=up` and `health=degraded`.

All evidence is synthetic and intended for testing/demo use.
