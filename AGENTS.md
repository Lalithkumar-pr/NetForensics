# NetForensics Development Rules

## Architecture Rule

The ONLY Python application source root is:

backend/app/

Do NOT create or recreate a `src/` directory.

Do NOT create:
- src/
- src/ingestion/
- src/correlation/
- src/reconstruction/
- src/visualization/

All future backend modules must be created under:

backend/app/

Current and planned structure:

backend/app/
├── ingestion/
├── normalization/
├── topology/
├── correlation/
├── reconstruction/
├── rca/
├── explanation/
├── api/
└── visualization/

Only create a directory when the corresponding implementation phase explicitly requests it.

## Phase Discipline

Implement ONLY the phase requested in the prompt.

Do not:
- anticipate future phases
- create placeholder folders for future phases
- create duplicate implementations
- reorganize the architecture
- introduce AI/ML
- add unnecessary dependencies

Never modify unrelated files.

## Current Phase

Phase 1 = Evidence Ingestion.

Phase 1 consists of:
- topology.json loading
- events.log loading
- traffic.pcap loading
- ingestion validation
- ingestion exceptions
- ingestion tests

Phase 1 does NOT include:
- normalization
- NetworkX graph modelling
- evidence correlation
- root-cause analysis
- reconstruction
- FastAPI
- React
- visualization
- AI/ML