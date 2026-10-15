# 🛡️ CAN-BUS Detection & Security Framework

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg?logo=react)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5-646CFF.svg?logo=vite)](https://vitejs.dev/)

An advanced automotive cybersecurity research platform for Controller Area Network (CAN) bus networks in connected vehicles. It features a multi-tiered **Intrusion Detection System (IDS)**, **Cryptographic Message Authentication**, an **ETAS/Bosch BUSMASTER-compatible Simulation Engine**, and a real-time **React Cybersecurity Dashboard**.

---

## 📌 Table of Contents
- [Overview & Architecture](#-overview--architecture)
- [Key Features](#-key-features)
- [Directory Structure](#-directory-structure)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Running the Application](#-running-the-application)
  - [1. Backend API & Telemetry Engine](#1-backend-api--telemetry-engine)
  - [2. Interactive Web Dashboard](#2-interactive-web-dashboard)
- [CLI Reference](#-cli-reference)
- [🛠️ BUSMASTER Simulation Engine](#️-busmaster-simulation-engine)
- [Intrusion Detection & Defense Pipeline](#-intrusion-detection--defense-pipeline)
- [REST API Endpoints](#-rest-api-endpoints)
- [Testing & Quality Assurance](#-testing--quality-assurance)
- [Safety Notice](#-safety-notice)
- [License](#-license)

---

## 🏗️ Overview & Architecture

Modern connected vehicles rely heavily on the CAN bus protocol for inter-ECU communications. However, broadcast-based CAN lacks native authentication, encryption, and sender verification, leaving vehicles vulnerable to packet injection, spoofing, replay, and denial-of-service (DoS) attacks.

This framework simulates realistic automotive network traffic, introduces attacks in a controlled environment, and detects intrusions using complementary defense mechanisms in real time:

```
                      +---------------------------------------+
                      |       Vehicle Simulator / ECUs        |
                      |  (Engine, Brake, Steering, Gateway)   |
                      +-------------------+-------------------+
                                          |
                                          v
+-----------------------+     +-----------+-----------+     +------------------------+
| Attack Simulator      | --> | Simulated CAN Bus     | <-- | BUSMASTER Engine       |
| (Flooding, Spoofing,  |     | (Virtual Interface)   |     | (Virtual Nodes, Trace, |
|  Fuzzing, Replay)     |     +-----------+-----------+     |  Fault Injection)      |
+-----------------------+                 |                 +------------------------+
                                          v
                              +-----------+-----------+
                              | CAN Collector Engine  |
                              +-----------+-----------+
                                          |
                   +----------------------+----------------------+
                   |                                             |
                   v                                             v
        +----------------------+                      +----------------------+
        | Rule-Based Detection |                      | ML Anomaly Detector  |
        | - Frequency / DLC    |                      | - Random Forest      |
        | - Range / ID Rules   |                      | - Feature Extractor  |
        +----------+-----------+                      +----------+-----------+
                   |                                             |
                   +----------------------+----------------------+
                                          v
                              +-----------+-----------+
                              | Decision Engine       |
                              | - Threat Scoring      |
                              | - Counter-measures    |
                              +-----------+-----------+
                                          |
                   +----------------------+----------------------+
                   |                                             |
                   v                                             v
        +----------------------+                      +----------------------+
        | SQLite Database Log  |                      | FastAPI WebSocket    |
        +----------------------+                      +----------+-----------+
                                                                 |
                                                                 v
                                                      +----------------------+
                                                      | React Web Dashboard  |
                                                      +----------------------+
```

---

## ✨ Key Features

- **Multi-Node CAN Simulator**: Realistic vehicle simulation with stateful virtual Electronic Control Units (Engine, Transmission, Brakes, Steering, Infotainment, Gateway).
- **BUSMASTER Simulation Engine**:
  - Full compatibility with ETAS/Bosch BUSMASTER `.log` trace format.
  - Independent virtual nodes with cyclic transmission schedules.
  - Live bus load calculation (0–100% bus utilization @ 500 kbps).
  - Built-in fault injection (babbling node bursts, payload corruption, bus-off).
  - Microsecond-accurate trace logging, export, and accelerated replay (1x to 50x).
- **Multi-Layer Intrusion Detection (IDS)**:
  - **Rule-Based Engine**: Validates CAN IDs, DLC lengths, payload boundaries, transmission cycle timings, and forbidden frame transitions.
  - **Machine Learning Detector**: Random Forest model trained on statistical sliding-window traffic features (entropy, mean interval, ID distribution).
  - **Cryptographic Authentication**: HMAC-SHA256 authenticated message digests with freshness sequence counters to prevent replay attacks.
- **Attack Generation Suite**: Programmable attacks for DoS/Flooding, payload fuzzing, ECU spoofing, and replay attacks.
- **Modern Web Dashboard**: Real-time React + Vite telemetry center with dark glassmorphic UI, live charts, alert feed, and dedicated BUSMASTER panel.
- **Extensible CLI**: Complete terminal management tool powered by Click and Rich console formatting.

---

## 📁 Directory Structure

```text
CAN-BUS-Detection/
├── config/                     # Configuration definitions
│   ├── can_ids.yaml            # Standard automotive CAN ID catalog
│   ├── config.yaml             # Core system & interface configuration
│   ├── detection_rules.yaml    # Security policies and threshold limits
│   └── security_policy.yaml    # Authentication and key management policies
├── dashboard/                  # React + Vite web dashboard
│   ├── public/                 # Static assets (favicons, icons)
│   ├── src/
│   │   ├── components/         # Modular UI panels (BusmasterPanel, etc.)
│   │   ├── App.jsx             # Main dashboard view & tabs
│   │   └── App.css             # Glassmorphic dark styling
│   ├── package.json            # Node.js dependencies
│   └── vite.config.js          # Vite bundler configuration
├── data/                       # Local database storage (.gitignored)
├── ml/                         # Pre-trained models and datasets
│   └── datasets/               # Training, testing, and benchmark CSVs
├── scripts/                    # Automation scripts
│   ├── generate_dataset.py     # Synthetic CAN traffic generator
│   └── train_model.py          # ML model trainer & evaluator
├── src/
│   └── can_security/           # Python core framework package
│       ├── api/                # FastAPI application, routes, and WebSockets
│       ├── attacks/            # Attack simulation modules (flooding, fuzzing)
│       ├── authentication/     # HMAC authentication & freshness counters
│       ├── can/                # CAN abstraction, collector, and BUSMASTER engine
│       │   ├── busmaster.py    # Complete BUSMASTER simulator & parser
│       │   ├── collector.py    # Asynchronous frame aggregator
│       │   ├── interface.py    # Virtual & physical CAN hardware interfaces
│       │   └── simulator.py    # Stateful vehicle simulation
│       ├── cli/                # Terminal CLI commands
│       ├── core/               # Data models, config loaders, exceptions
│       ├── database/           # SQLite telemetry & alerts persistence
│       ├── decision/           # Threat scoring and response engine
│       ├── detection/          # Rule-based and ML detection engines
│       ├── ecu/                # Virtual ECUs (Engine, Brake, Steering, etc.)
│       └── features/           # Sliding-window statistical feature extractor
├── tests/                      # Pytest test suite
│   ├── integration/            # API and end-to-end integration tests
│   └── unit/                   # Unit tests (busmaster, security, ECUs)
├── pyproject.toml              # Python project metadata & tool configurations
├── requirements.txt            # Python production dependencies
├── requirements-dev.txt        # Development, testing, and linting tools
└── README.md                   # Project documentation
```

---

## 💻 Prerequisites

- **Python**: Version `3.11` or higher
- **Node.js**: Version `18.x` or higher (with `npm`)
- **Git**

---

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Ranjith9916/CAN-BUS-Detection.git
cd CAN-BUS-Detection
```

### 2. Set Up Python Virtual Environment
```bash
python -m venv venv

# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# On Linux / macOS:
source venv/bin/activate
```

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .
```

### 4. Install Dashboard Dependencies
```bash
cd dashboard
npm install
cd ..
```

---

## 🖥️ Running the Application

### 1. Backend API & Telemetry Engine
Start the FastAPI server (runs on `http://localhost:8000` with WebSocket on `ws://localhost:8000/ws`):
```bash
python -m can_security.cli.main start
```

Interactive Swagger documentation is available at:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### 2. Interactive Web Dashboard
In a separate terminal, launch the React development server:
```bash
cd dashboard
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser to access:
- **Overview**: Live status, threat gauge, event throughput, and security status.
- **Events**: Stream of received CAN frames with filtering and inspection.
- **Alerts**: Flagged security violations with rule IDs and severity levels.
- **BUSMASTER Simulator**: Full multi-node control, fault injection, live trace monitor, and manual transmission.
- **Operations / Controls**: Attack launcher, playback controls, and defense toggles.

---

## ⌨️ CLI Reference

The CLI provides comprehensive commands for testing, simulation, and analysis:

```bash
# Check system health, configuration, and interface status
python -m can_security.cli.main health

# Run standard vehicle CAN simulation for 10 seconds
python -m can_security.cli.main simulate --duration 10

# Train the ML intrusion detection model
python -m can_security.cli.main train

# Evaluate model accuracy, precision, recall, and F1 score
python -m can_security.cli.main evaluate

# Generate synthetic dataset for training
python -m can_security.cli.main generate-dataset --duration 30 --output ml/datasets/

# Run BUSMASTER simulation with real-time console telemetry
python -m can_security.cli.main busmaster-simulate --duration 10 --bus-speed 500000

# Replay a BUSMASTER trace through the intrusion detection engine
python -m can_security.cli.main busmaster-replay --file logs/busmaster_latest.log --speed 2.0

# Export simulation traffic to standard BUSMASTER .log format
python -m can_security.cli.main busmaster-export --duration 5 --output logs/trace_export.log
```

---

## 🛠️ BUSMASTER Simulation Engine

The BUSMASTER engine (`can_security.can.busmaster`) models an automotive CAN network adhering to ETAS/Bosch BUSMASTER specifications:

### Virtual ECU Nodes
- **Engine_Node** (`0x100` @ 10ms, `0x104` @ 100ms): Dynamic RPM, throttle position, engine temperature.
- **Brake_Node** (`0x102` @ 10ms): Brake pedal pressure, brake switch, ABS status.
- **Steering_Node** (`0x103` @ 20ms): Steering angle and angular velocity.
- **Transmission_Node** (`0x105` @ 50ms): Current gear ratio, shift request flags, clutch state.
- **Cluster_Node** (`0x101` @ 100ms, `0x107` @ 200ms): Vehicle speed, odometer, turn indicators.
- **Gateway_Tester_Node** (`0x7DF` @ 500ms): OBD-II / UDS diagnostic queries.

### Standard Trace Compatibility
Exports and parses genuine BUSMASTER `.log` files:
```text
***BUSMASTER Log and Trace File***
***START DATE AND TIME 15:10:2026 10:00:00:000***
***PROTOCOL CAN***
***BUS SPEED 500000 bps***
***CHANNEL 1***
***START CHANNEL 1***
***MODE SIMULATION***
***FILTER NONE***
***<Time><Tx/Rx><Channel><CAN ID><Type><DLC><DataBytes>***
00:00:01.0100 s 1 Tx 0x100 s 8 12 34 56 78 90 AB CD EF
00:00:01.0200 s 1 Tx 0x102 s 8 00 00 00 00 00 00 00 01
```

---

## 🛡️ Intrusion Detection & Defense Pipeline

| Defense Layer | Mechanism | Target Attack Vectors |
|---|---|---|
| **Rule Engine** | Cycle time thresholds, ID white-listing, DLC verification, signal range checks | DoS, Bus Flooding, Payload Fuzzing |
| **ML Anomaly Detector** | Random Forest / Isolation Forest on sliding-window entropy and frequency | Zero-day anomalies, Subtle behavioral drift |
| **Freshness Counter** | Monotonically incrementing per-session sequence counters | Replay attacks, Delayed frame injection |
| **HMAC Authentication** | Truncated HMAC-SHA256 message authentication codes | Masquerade / Spoofing attacks |

---

## 🌐 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | System health, message count, alert counts |
| `GET` | `/api/events` | Historical CAN events stream |
| `GET` | `/api/alerts` | Active and historical intrusion alerts |
| `POST` | `/api/simulation/start` | Start vehicle background simulation |
| `POST` | `/api/simulation/stop` | Stop vehicle simulation |
| `POST` | `/api/attack/start` | Launch attack scenario (flooding, fuzzing, spoofing) |
| `POST` | `/api/attack/stop` | Terminate running attack |
| `GET` | `/api/busmaster/status` | BUSMASTER status, bus load %, frame totals |
| `GET` | `/api/busmaster/nodes` | List virtual nodes, schedules, and metrics |
| `POST` | `/api/busmaster/nodes/toggle` | Enable / disable simulated ECU node |
| `POST` | `/api/busmaster/start` | Start BUSMASTER engine |
| `POST` | `/api/busmaster/stop` | Stop BUSMASTER engine |
| `POST` | `/api/busmaster/transmit` | Inject manual single-shot CAN frame |
| `POST` | `/api/busmaster/fault` | Inject node fault (burst, corrupt, bus_off) |
| `GET` | `/api/busmaster/trace` | Retrieve circular trace buffer |
| `GET` | `/api/busmaster/export-log` | Download `.log` file in native BUSMASTER format |
| `POST` | `/api/busmaster/upload-log` | Upload and replay external `.log` file |
| `WS` | `/ws` | Real-time WebSocket telemetry and alert feed |

---

## 🧪 Testing & Quality Assurance

Run the test suite using `pytest`:

```bash
# Run all unit tests
pytest tests/unit/ -v

# Run BUSMASTER specific tests
pytest tests/unit/test_busmaster.py -v

# Run integration tests
pytest tests/integration/ -v

# Run code style and lint checks
ruff check .
black --check .
```

---

## ⚠️ Safety Notice

> **Important**: This framework is designed exclusively for **academic research, education, and cybersecurity testing** in simulated or isolated laboratory bench environments. **Never** connect experimental hardware or inject simulated attack traffic into real, active, or road-operating motor vehicles.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for complete details.
