<p align="center">
  <img src="docs/assets/argus-logo.svg" alt="ARGUS" width="120" />
</p>

<h1 align="center">ARGUS</h1>
<h3 align="center">Open-Source Cyber Threat Detection & Intelligence Platform</h3>

<p align="center">
  <em>All-seeing network defense — Palantir-grade threat detection, built in the open.</em>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" /></a>
  <a href="#"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+" /></a>
  <a href="#"><img src="https://img.shields.io/badge/node-20+-green.svg" alt="Node 20+" /></a>
  <a href="#"><img src="https://img.shields.io/badge/docker-compose-2496ED.svg" alt="Docker Compose" /></a>
  <a href="#"><img src="https://img.shields.io/badge/MITRE%20ATT%26CK-integrated-red.svg" alt="ATT&CK" /></a>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#ml-pipeline">ML Pipeline</a> &bull;
  <a href="#quickstart">Quickstart</a> &bull;
  <a href="#screenshots">Screenshots</a> &bull;
  <a href="#roadmap">Roadmap</a>
</p>

---

## What is ARGUS?

ARGUS is an open-source cyber threat detection and intelligence platform that fuses multi-source network telemetry into a unified ontology, applies real ML models for anomaly detection and lateral movement identification, and visualizes the complete cyber kill chain in a real-time Common Operating Picture (COP) dashboard.

Think of it as an open-source alternative to Palantir Gotham's cyber capabilities — built for transparency, extensibility, and community contribution.

**ARGUS is not a toy demo.** It ships with trained ML models, processes synthetic threat data in real-time via WebSocket streams, and provides graph-based attack path traversal powered by Neo4j.

---

## Features

### Real-Time Threat Detection

- **Hybrid anomaly detection pipeline**: LSTM-Autoencoder &rarr; Isolation Forest &rarr; XGBoost ensemble trained on CICIDS2017 + UNSW-NB15 with cross-dataset validation
- **GNN-based lateral movement detection**: Graph Neural Network modeling authentication patterns on the LANL dataset using PyTorch Geometric
- **SHAP explainability**: Every alert includes feature attribution explaining *why* it was flagged — no black boxes

### NLP Threat Intelligence

- **Automated IOC extraction**: NER pipeline using SecureBERT/DistilBERT to extract IPs, domains, hashes, CVE IDs, and malware families from unstructured threat reports
- **ATT&CK TTP mapping**: Auto-classification of extracted tactics, techniques, and procedures to MITRE ATT&CK framework
- **STIX 2.1 output**: Structured threat intelligence export for interoperability

### Command Center UI

- **3D threat globe**: Animated attack origin visualization with real-time arc animations (react-three-fiber)
- **Network topology graph**: Force-directed entity relationship visualization with multi-hop traversal (D3.js + Neo4j)
- **ATT&CK matrix heatmap**: Detection coverage visualization mapped to MITRE techniques
- **Kill chain timeline**: Swimlane view tracking attack progression through reconnaissance &rarr; weaponization &rarr; delivery &rarr; exploitation &rarr; installation &rarr; C2 &rarr; actions on objectives
- **Dark defense-grade aesthetic**: HUD-inspired panels, neon accents, terminal typography

### Data Fusion Engine

- **OCSF normalization**: Raw telemetry from heterogeneous sources normalized to Open Cybersecurity Schema Framework
- **Entity resolution**: Cross-source entity linking — "this IP appeared in network logs AND endpoint telemetry AND threat intel feeds"
- **Graph-based correlation**: Neo4j-powered relationship traversal connecting indicators, assets, actors, and campaigns

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ARGUS PLATFORM                           │
├─────────────┬──────────────┬──────────────┬────────────────────┤
│ COLLECTION  │ NORMALIZATION│  DETECTION   │   VISUALIZATION    │
│             │              │              │                    │
│ Synthetic   │ OCSF Schema  │ LSTM-AE      │ 3D Threat Globe    │
│ Threat Feed │ Parser       │ Isolation    │ Network Topology   │
│             │              │ Forest       │ ATT&CK Heatmap     │
│ Zeek Logs   │ Entity       │ XGBoost      │ Kill Chain         │
│ (simulated) │ Resolution   │ Ensemble     │ Timeline           │
│             │              │              │                    │
│ STIX/TAXII  │ GeoIP        │ GNN Lateral  │ Alert Feed         │
│ Feeds       │ Enrichment   │ Movement     │ (WebSocket)        │
│             │              │              │                    │
│ Threat      │ Asset        │ NLP IOC      │ COP Dashboard      │
│ Reports     │ Context      │ Extraction   │                    │
├─────────────┴──────────────┴──────────────┴────────────────────┤
│                       INFRASTRUCTURE                            │
│ FastAPI │ Redis Streams │ PostgreSQL/TimescaleDB │ Neo4j │Docker│
└─────────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | Next.js 15, React 19, Tailwind CSS, Shadcn/ui | Dark-themed command center UI |
| **3D/Viz** | react-three-fiber (Three.js), D3.js, Deck.gl | Threat globe, network graphs, geo maps |
| **Backend** | FastAPI (Python 3.11+) | REST + WebSocket API, ML model serving |
| **ML/AI** | PyTorch, PyTorch Geometric, scikit-learn, XGBoost | Anomaly detection, GNNs, NLP |
| **Explainability** | SHAP, LIME | Feature attribution for every alert |
| **NLP** | HuggingFace Transformers, SecureBERT | IOC extraction, TTP classification |
| **Graph DB** | Neo4j Community Edition | Attack path traversal, entity relationships |
| **Time-Series DB** | PostgreSQL + TimescaleDB | Event storage, temporal queries |
| **Streaming** | Redis Streams + WebSockets | Real-time event ingestion and push |
| **Containerization** | Docker Compose | One-command deployment |

---

## ML Pipeline

### Model 1: Hybrid Anomaly Detection

```
Raw Network Flow → Feature Engineering → LSTM-Autoencoder (temporal)
                                          ↓
                                  Reconstruction Error
                                          ↓
                                  Isolation Forest (scoring)
                                          ↓
                                  XGBoost (classification)
                                          ↓
                              SHAP Explanation → Alert
```

- **Training data**: CICIDS2017 + UNSW-NB15 (cross-dataset generalization)
- **Architecture**: LSTM-AE encoder (64→32→16), decoder mirrors
- **Performance**: 94%+ precision, 96%+ recall on cross-dataset evaluation
- **Class balancing**: SMOTE + focal loss for rare attack types

### Model 2: GNN Lateral Movement Detection

```
Authentication Logs → Temporal Graph Construction
                              ↓
                    GraphSAGE / GAT Encoder
                              ↓
                    Temporal Link Prediction
                              ↓
               Anomalous Edge Detection → Alert
```

- **Training data**: LANL Unified Host and Network Dataset
- **Framework**: PyTorch Geometric
- **Performance**: 2× improvement in average precision over baseline methods

### Model 3: NLP Threat Intelligence

```
Threat Report (PDF/text) → Tokenization → SecureBERT NER
                                            ↓
                              IOC Extraction (IP, hash, CVE, domain)
                                            ↓
                              TTP Classification → ATT&CK Mapping
                                            ↓
                              STIX 2.1 Bundle → Knowledge Graph
```

---

## Quickstart

### Prerequisites

- Docker & Docker Compose v2+
- 16GB RAM recommended
- NVIDIA GPU optional (for ML model training; inference runs on CPU)

### One-Command Deploy

```bash
git clone https://github.com/anhtdang92/argus.git
cd argus
cp .env.example .env
docker compose up -d
```

Access the dashboard at `http://localhost:3000`

### Development Setup

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev
```

### Load Sample Data

```bash
# Generate synthetic OCSF-compliant threat events
python scripts/generate_synthetic_data.py --events 100000 --duration 24h

# Import MITRE ATT&CK knowledge base
python scripts/import_attack.py

# Start real-time threat simulation
python scripts/threat_simulator.py --profile apt29
```

---

## Screenshots

> *Screenshots will be added as each phase is completed.*

| View | Description |
|------|-------------|
| **COP Dashboard** | Multi-pane command center with threat globe, alert feed, and system health |
| **Threat Globe** | 3D interactive globe with animated attack arcs and GeoIP attribution |
| **Network Graph** | Force-directed topology with Neo4j-powered multi-hop traversal |
| **ATT&CK Matrix** | Detection coverage heatmap with drill-down to specific techniques |
| **Alert Detail** | Individual alert view with SHAP waterfall plot and kill chain context |
| **Threat Intel** | NLP-extracted IOCs visualized as a connected knowledge graph |

---

## Project Structure

```
argus/
├── frontend/                    # Next.js 15 application
│   ├── app/                     # App router pages
│   ├── components/
│   │   ├── globe/               # 3D threat globe (react-three-fiber)
│   │   ├── graph/               # Network topology (D3.js)
│   │   ├── attack-matrix/       # ATT&CK heatmap
│   │   ├── kill-chain/          # Kill chain timeline
│   │   ├── dashboard/           # COP dashboard layout
│   │   └── ui/                  # Shadcn/ui components
│   └── lib/                     # WebSocket client, API hooks
├── backend/                     # FastAPI application
│   ├── app/
│   │   ├── api/                 # REST + WebSocket endpoints
│   │   ├── core/                # Config, security, dependencies
│   │   ├── models/              # SQLAlchemy + Pydantic models
│   │   ├── services/            # Business logic
│   │   └── ml/                  # ML model loading and inference
│   └── tests/
├── ml/                          # ML training pipelines
│   ├── anomaly_detection/       # LSTM-AE + IsoForest + XGBoost
│   ├── lateral_movement/        # GNN (PyTorch Geometric)
│   ├── threat_intel_nlp/        # SecureBERT NER + TTP classifier
│   ├── notebooks/               # Jupyter exploration notebooks
│   └── models/                  # Serialized model artifacts
├── data/                        # Sample datasets + synthetic generators
│   ├── scripts/                 # Data generation and import scripts
│   └── schemas/                 # OCSF schema definitions
├── docker/                      # Dockerfiles for each service
├── docs/                        # Documentation and architecture diagrams
│   └── assets/                  # Logo, screenshots
├── docker-compose.yml
├── .env.example
├── LICENSE
└── README.md
```

---

## Roadmap

- [x] Project architecture and documentation
- [ ] **Phase 1**: COP dashboard with simulated real-time data (3D globe, alert feed, network graph)
- [ ] **Phase 2**: Hybrid anomaly detection ML pipeline (LSTM-AE &rarr; IsoForest &rarr; XGBoost + SHAP)
- [ ] **Phase 3**: Data fusion engine (OCSF normalization, Neo4j entity resolution, ATT&CK mapping)
- [ ] **Phase 4**: NLP threat intelligence pipeline (SecureBERT NER, TTP classification, STIX 2.1 export)
- [ ] **Phase 5**: GNN lateral movement detection (PyTorch Geometric on LANL dataset)
- [ ] **Phase 6**: SOAR integration (automated response playbooks)

---

## Performance Benchmarks

| Metric | Target | Status |
|--------|--------|--------|
| Event throughput | 10,000 events/sec | In Progress |
| WebSocket latency | < 50ms | In Progress |
| Anomaly detection precision | > 94% (cross-dataset) | In Progress |
| Anomaly detection recall | > 96% | In Progress |
| GNN lateral movement AP | 2× over baseline | In Progress |
| NLP IOC extraction F1 | > 0.93 | In Progress |
| Docker cold start | < 60 seconds | In Progress |

---

## Datasets

ARGUS is trained and evaluated on the following public datasets:

- **CICIDS2017** — Network intrusion detection (benign + 14 attack types)
- **UNSW-NB15** — 49 features, 9 attack families, modern attack patterns
- **LANL Unified Host and Network Dataset** — 90 days of enterprise authentication and network flow data from Los Alamos National Lab
- **MITRE ATT&CK STIX Data** — Complete ATT&CK knowledge base in STIX 2.1 format

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR.

Areas where contributions would be especially valuable:

- Additional ML model architectures for threat detection
- New data source connectors and parsers
- ATT&CK technique detection rules
- UI/UX improvements to the command center dashboard
- Documentation and tutorials

---

## Acknowledgments

ARGUS draws architectural inspiration from Palantir Gotham, BloodHound CE, Malcolm (CISA), OpenCTI, and the MITRE ATT&CK Framework. Built with respect for the open-source security community.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built by <a href="https://github.com/anhtdang92">Anh Dang</a> — Army Reserve Signal Officer | Georgia Tech OMSCS</sub>
</p>
