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
├── src/
│   ├── ingestion/
│   ├── correlation/
│   ├── reconstruction/
│   └── visualization/
│
├── tests/
│
└── docs/
```

## Features

- **Ingestion**: Parsers for network topologies, syslog/event logs, and PCAP packet captures.
- **Correlation**: Cross-correlates multi-source network signals to detect anomalies.
- **Reconstruction**: Reconstructs incident timelines and identifies root causes.
- **Visualization**: Visualizes topology state changes and packet flows during network incidents.
