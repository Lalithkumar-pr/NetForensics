# NetForensics

NetForensics is a network forensics analysis framework for event ingestion, incident correlation, timeline reconstruction, and visualization.

## Directory Structure

```
NetForensics/
├── README.md
├── LICENSE
├── .gitignore
│
├── data/
│   └── scenarios/
│       └── S01_switch_uplink_failure/
│           ├── topology.json
│           ├── events.log
│           ├── traffic.pcap
│           ├── ground_truth.json
│           ├── README.md
│           ├── schema.md
│           └── MANIFEST.json
│
├── backend/
│   └── app/
│       └── ingestion/
│
├── tests/
│
└── docs/
```

## Features

- **Ingestion**: Parsers for network topologies, event logs, and PCAP packet captures.
- **Validation**: Handles missing files, malformed evidence, invalid topology structures, and invalid PCAP input.
- **Scenario Support**: Loads structured network incident evidence from scenario datasets.
