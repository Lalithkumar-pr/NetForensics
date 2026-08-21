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
│       ├── ingestion/
│       ├── normalization/
│       └── correlation/
│
├── tests/
│   ├── test_ingestion.py
│   ├── test_normalization.py
│   └── test_correlation.py
│
└── docs/
```

## Features

- **Ingestion**: Parsers for network topologies, event logs, and PCAP packet captures.
- **Validation**: Handles missing files, malformed evidence, invalid topology structures, and invalid PCAP input.
- **Normalization**: Converts heterogeneous evidence sources (event logs, PCAP traffic) and network topologies into standardized internal representations.
- **Evidence Correlation**: Deterministically correlates normalized evidence using temporal, entity, topology, and network-flow relationships (establishes relationships between records; does not yet determine root cause).
- **Scenario Support**: Loads structured network incident evidence from scenario datasets.
