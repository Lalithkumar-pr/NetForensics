# NetForensics

NetForensics is a network failure forensics and root-cause reconstruction framework that converts heterogeneous network evidence (`topology.json`, `events.log`, `traffic.pcap`) into an auditable, ranked root-cause analysis with diagnostic confidence ratings.

## How NetForensics Eliminates the Manual Workflow

### Traditional Forensic Workflow
```
Inspect logs -> inspect PCAP -> inspect topology -> correlate timestamps -> identify affected hosts -> form hypotheses -> manually compare -> determine root cause
```
*Disadvantages*: Time-consuming, prone to human bias, difficult to audit, requires high manual correlation effort across multiple tools.

### NetForensics Workflow
```
Raw Evidence -> Ingestion -> Normalization -> Correlation -> Reconstruction -> Validation -> Auditable Diagnostic Dashboard
```
*Advantages*: 100% deterministic, evidence-driven, zero AI hallucinations, instant automated hypothesis ranking with complete ID-level evidence traceability.

> **NO AI / ML / LLM Policy**: NetForensics contains **ZERO** AI, machine learning, neural networks, or external LLM API calls. All forensic reasoning is strictly rule-based, deterministic, explainable, and reproducible.

---

## Directory Structure

```
NetForensics/
├── README.md
├── LICENSE
├── .gitignore
├── run_demo.py                     # Zero-dependency HTTP server runner for instant demo
│
├── data/
│   └── scenarios/                  # Structured network incident datasets (S01 to S09)
│       ├── S01_switch_uplink_failure/
│       ├── S02_single_access_port_failure/
│       ├── S03_router_interface_failure/
│       ├── S04_routing_failure/
│       ├── S05_vlan_misconfiguration/
│       ├── S06_arp_resolution_failure/
│       ├── S07_dns_failure/
│       ├── S08_degraded_link_packet_loss/
│       └── S09_dhcp_failure/
│
├── backend/
│   └── app/
│       ├── ingestion/              # Phase 1: Topology, Event log, and PCAP loaders
│       ├── normalization/          # Phase 2: Heterogeneous evidence normalization
│       ├── correlation/            # Phase 3: Temporal, entity, topology, and flow correlation
│       ├── reconstruction/         # Phase 4: Root-cause hypothesis generation & scoring engine
│       ├── validation/             # Phase 5: Diagnostic confidence & investigation guidance
│       ├── api/                    # Final Phase: REST API endpoints (/api/scenarios, /api/investigate)
│       └── main.py                 # FastAPI Application server
│
├── frontend/                       # Interactive Investigation Dashboard Presentation UI
│   ├── index.html
│   ├── styles.css
│   └── app.js
│
├── tests/                          # Comprehensive pytest test suite
│   ├── test_ingestion.py
│   ├── test_normalization.py
│   ├── test_correlation.py
│   ├── test_reconstruction.py
│   ├── test_validation.py
│   └── test_api.py
│
└── docs/                           # Architecture documentation
```

---

## How to Run the Demo Dashboard

### Option A: Zero-Dependency Demo Server (Recommended for Instant Demo)

Run the built-in HTTP server runner (requires only Python standard library):

```bash
python run_demo.py
```

Then open your browser to:
**`http://localhost:8000`**

### Option B: FastAPI + Uvicorn Server

```bash
python -m uvicorn backend.app.main:app --port 8000 --reload
```

Then open your browser to:
**`http://localhost:8000`**

---

## How to Run Tests

Run the complete test suite (74 tests covering all 5 phases):

```bash
python -m pytest -v
```

---

## Example Investigation Workflow

1. Open `http://localhost:8000` in your web browser.
2. Select an incident scenario from the dropdown (e.g. `S01 - Switch Uplink Failure`, `S04 - Routing Failure`, `S07 - DNS Failure`, `S08 - Degraded Link / Packet Loss`, `S09 - DHCP Failure`).
3. Click **INVESTIGATE**.
4. Review the generated Forensic Investigation Dashboard:
   - **Spotlight Banner**: Primary Root Cause, Type, Target Entity, Score, Confidence.
   - **Auditable Explanation**: Textual evidence breakdown with referenced event IDs.
   - **Score Breakdown**: Decomposed component progress bars for Evidence Support, Temporal, Topology, Propagation, Specificity, and Contradictions.
   - **Diagnostic Validation**: Evidence Coverage, Source Diversity, Completeness, and Recommended Verification Steps.
   - **Impact & Propagation**: Affected vs Unaffected Devices.
   - **Supporting & Contradicting Evidence Cards**: Detailed log/packet event cards.
   - **Alternative Candidates Table**: Ranked list of runner-up failure hypotheses.
   - **Timeline**: Chronological event ordering.
   - **Forensic Traceability**: Traceable supporting & contradicting event IDs (`log_5`, `pcap_12`).

---

## Deterministic Scoring Formula

Phase 4 hypothesis ranking score ($0.0 \text{ to } 1.0$):

$$\text{Score} = \max\left(0.0, \min\left(1.0, 0.30 \cdot \text{Support} + 0.15 \cdot \text{Temporal} + 0.20 \cdot \text{Topology} + 0.25 \cdot \text{Propagation} + 0.10 \cdot \text{Specificity} - \text{ContradictionPenalty}\right)\right)$$

Phase 5 Diagnostic Confidence:

$$\text{DiagnosticConfidence} = \max\left(0.0, \min\left(1.0, 0.25 \cdot H_{\text{score}} + 0.25 \cdot C_{\text{coverage}} + 0.20 \cdot D_{\text{diversity}} + 0.15 \cdot M_{\text{completeness}} + 0.15 \cdot S_{\text{separation}} - 0.40 \cdot P_{\text{contradiction}}\right)\right)$$

> **Ground-Truth Isolation**: Production code in `backend/app/` NEVER reads or references `ground_truth.json`. Ground truth is used strictly by automated tests as an evaluation oracle.
