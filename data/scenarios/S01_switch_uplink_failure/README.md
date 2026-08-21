# Scenario S01: Switch Uplink Failure

## Overview
This scenario models a physical/logical uplink failure between an access switch (`SW-ACCESS-01`) and a core switch (`SW-CORE-01`).

## Contents
- `topology.json`: Network topology baseline before and during failure.
- `events.log`: Syslog messages and SNMP traps capturing link state transitions.
- `traffic.pcap`: Packet capture snippet recorded during the uplink drop.
- `ground_truth.json`: Expected forensic timeline and root cause annotations.
- `schema.md`: Specifications for dataset files in this scenario.
- `MANIFEST.json`: Metadata, checksums, and scenario manifest.
