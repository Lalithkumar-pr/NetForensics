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
│       ├── correlation/
│       ├── reconstruction/
│       └── validation/
│
├── tests/
│   ├── test_ingestion.py
│   ├── test_normalization.py
│   ├── test_correlation.py
│   ├── test_reconstruction.py
│   └── test_validation.py
│
└── docs/
```

## Forensic Processing Pipeline

```
Raw Evidence
    |
    v
Ingestion
    |
    v
Normalization
    |
    v
Correlation
    |
    v
Reconstruction
    |
    v
Validation & Confidence
    |
    v
Auditable Diagnostic Report
```

## Features

- **Ingestion**: Parsers for network topologies, event logs, and PCAP packet captures.
- **Normalization**: Converts heterogeneous evidence sources (event logs, PCAP traffic) and network topologies into standardized internal representations.
- **Evidence Correlation**: Deterministically correlates normalized evidence using temporal, entity, topology, and network-flow relationships.
- **Evidence Reconstruction**: Uses deterministic hypothesis generation and evidence scoring to rank probable root causes.
- **Evidence Validation & Diagnostic Confidence**: Evaluates evidence coverage, source diversity, completeness, contradictions, hypothesis separation, missing evidence, and recommended next investigation steps.

### Phase 5: Evidence Validation & Diagnostic Confidence

Phase 5 answers: *"How confident should an investigator be in the reconstruction, what evidence makes it trustworthy, what evidence is missing, what contradictions remain, and what should be checked next?"*

- **Difference Between RCA Score & Diagnostic Confidence**: Phase 4 hypothesis score evaluates how well a hypothesis explains the observed evidence. Phase 5 diagnostic confidence evaluates how trustworthy that conclusion is given evidence coverage, source diversity, contradiction state, completeness, and separation margin.
  > **Diagnostic confidence is not a statistical probability. It is a deterministic measure of evidential support and reconstruction quality.**
- **Evidence Coverage**: Assesses breadth of support across log, packet, topology, temporal, and propagation dimensions.
- **Source Diversity**: Measures independent corroboration across event logs, PCAP traffic, and network topology.
- **Evidence Completeness**: Compares observed evidence against generic failure-signature requirements and identifies missing signals.
- **Contradiction Analysis**: Evaluates contradicting evidence event IDs, severity levels, and applies penalty deductions.
- **Hypothesis Separation**: Measures score margin between leading hypothesis and runner-up to flag ambiguous rankings.
- **Confidence Bands**: Deterministically maps confidence scores to qualitative bands: `HIGH` (>= 0.80), `MODERATE` (>= 0.60), `LOW` (>= 0.40), `INSUFFICIENT` (< 0.40).
- **Missing Evidence Detection**: Identifies unconfirmed diagnostic signals needed to validate hypotheses.
- **Investigation Recommendations**: Generates non-modifying, ordered verification steps for investigators.
- **Auditability & Traceability**: All conclusions remain traceable to specific `EvidenceEvent` IDs.
- **Determinism**: 100% rule-based and reproducible with zero randomness, AI/ML, or external APIs.
- **Ground-Truth Isolation**: Production code never accesses `ground_truth.json`, preserving strict separation between evidence reasoning and evaluation oracles.
