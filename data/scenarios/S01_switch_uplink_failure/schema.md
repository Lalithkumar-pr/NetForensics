# Data Schemas for Scenario S01

## 1. `topology.json`
Represents network devices, interfaces, and active links.
- `nodes`: List of objects (`id`, `type`, `hostname`, `ip`).
- `links`: List of objects (`id`, `source`, `target`, `status`).

## 2. `events.log`
Log format: `<Timestamp> <Host> <Facility/Severity> <Message>`
Example:
`2026-08-21T09:00:00Z SW-ACCESS-01 LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down`

## 3. `traffic.pcap`
Standard PCAP packet capture file containing network traffic traces recorded during the scenario window.

## 4. `ground_truth.json`
Incidents annotations used for evaluating reconstruction accuracy.
- `scenario_id`: Unique identifier for the scenario.
- `root_cause`: Key component or link failure cause.
- `timeline`: Array of event objects with `timestamp`, `event_type`, and `impact`.

## 5. `MANIFEST.json`
Metadata listing all files, versioning, format specifications, and file integrity details.
