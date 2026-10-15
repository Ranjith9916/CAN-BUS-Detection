# CAN Security Framework & BUSMASTER Simulator

An advanced automotive cybersecurity research platform for CAN bus networks, providing:
- **Intrusion Detection System (IDS)**: Rule engine, ML anomaly detector, sequence freshness, and cryptographic authentication.
- **BUSMASTER Simulation Engine**: ETAS/Bosch BUSMASTER-compatible multi-node CAN simulation, live trace monitoring, fault injection, and native `.log` trace recording & replay.
- **REST API & WebSocket**: High-performance FastAPI backend with real-time telemetry streaming.
- **Interactive Web Dashboard**: React + Vite cybersecurity control center with a dedicated BUSMASTER Simulator tab.

---

## 🛠️ BUSMASTER Simulator Architecture

The BUSMASTER Simulator module (`can_security.can.busmaster`) models an automotive CAN bus network adhering to BUSMASTER specifications:

### 1. Virtual Node Network (ECUs)
Simulates realistic, synchronized multi-ECU communications:
- **Engine_Node** (`0x100` @ 10ms, `0x104` @ 100ms): Correlated RPM, throttle, engine temperature.
- **Brake_Node** (`0x102` @ 10ms): Brake pedal pressure, brake switch, ABS activation status.
- **Steering_Node** (`0x103` @ 20ms): Steering wheel angle and torque rate.
- **Transmission_Node** (`0x105` @ 50ms): Current gear, shift flags, clutch status.
- **Cluster_Node** (`0x101` @ 100ms, `0x107` @ 200ms): Vehicle speed, odometer, indicator flags.
- **Gateway_Tester_Node** (`0x7DF` @ 500ms): OBD-II / UDS diagnostic request simulation.
- **Attacker_Node** (Configurable): On-demand injection for flooding, spoofing, fuzzing, and burst attacks.

### 2. BUSMASTER Log Format Compatibility
Fully supports standard ETAS/Bosch BUSMASTER `.log` file headers and message records:
```text
***BUSMASTER Log and Trace File***
***START DATE AND TIME 06:10:2026 15:30:00:000***
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

- **`BusmasterLogWriter`**: Exports simulation traffic directly to `.log` trace files.
- **`BusmasterLogReader`**: Parses standard BUSMASTER `.log` files with microsecond timestamps, channels, directions, and hex payloads.
- **`BusmasterPlaybackEngine`**: Replays BUSMASTER trace logs in real-time (1x) or accelerated rate (2x, 5x, 10x, 50x) through the intrusion detection engine.

### 3. Fault & Attack Injection
- **Burst Frames**: Injects rapid bursts of frames to simulate node babbling.
- **Corrupt Payload**: Injects extreme out-of-range payloads to test boundary rules.
- **Bus-Off Simulation**: Simulates node disconnect or bus-off states.
- **Manual Console**: Transmits single-shot custom frames from the UI or API.

---

## 🚀 CLI Commands

Run BUSMASTER commands directly from the terminal:

### 1. Run BUSMASTER Simulation
```bash
python -c "import sys; sys.path.insert(0, 'src'); from can_security.cli.main import main; main()" busmaster-simulate --duration 10 --bus-speed 500000
```
- Displays live nodes, cyclic messages, transmission rate, bus load %, and active trace lines.
- Automatically saves trace to `logs/busmaster_latest.log` (or custom path with `--export-log`).

### 2. Replay BUSMASTER Log Through IDS
```bash
python -c "import sys; sys.path.insert(0, 'src'); from can_security.cli.main import main; main()" busmaster-replay --file logs/busmaster_latest.log --speed 2.0
```
- Reads the BUSMASTER trace and feeds every frame into the detection pipeline.
- Reports security violations and anomalies.

### 3. Export Trace to BUSMASTER Format
```bash
python -c "import sys; sys.path.insert(0, 'src'); from can_security.cli.main import main; main()" busmaster-export --duration 5 --output logs/trace_export.log
```

---

## 🌐 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/busmaster/status` | Simulator status (running, bitrate, bus load, total msgs) |
| `GET` | `/api/busmaster/nodes` | List virtual nodes, message schedules, and stats |
| `POST` | `/api/busmaster/nodes/toggle` | Enable or disable a simulated node |
| `POST` | `/api/busmaster/start` | Start BUSMASTER network simulation |
| `POST` | `/api/busmaster/stop` | Stop BUSMASTER simulation |
| `POST` | `/api/busmaster/transmit` | Send a manual single-shot CAN frame |
| `POST` | `/api/busmaster/fault` | Inject fault into a node (burst, corrupt, bus_off) |
| `GET` | `/api/busmaster/trace` | Get recent circular trace buffer |
| `GET` | `/api/busmaster/export-log` | Download trace in genuine BUSMASTER `.log` format |
| `POST` | `/api/busmaster/upload-log` | Upload and replay a `.log` file into the security engine |

---

## 💻 Web Dashboard

Start the FastAPI backend:
```bash
python -m can_security.cli.main start
```

Start the Vite React frontend:
```bash
cd dashboard
npm run dev
```

Open `http://localhost:5173` and click the **"BUSMASTER Simulator"** tab to access:
- **Live Bus Statistics & Load Gauge** (0–100% bus utilization at 500 kbps).
- **Virtual Node Cards** with individual Enable/Disable toggles and instant fault injection buttons.
- **BUSMASTER Trace Window** with color-coded Tx/Rx tags, CAN IDs, DLC, and hex byte viewer with live auto-scroll and filtering.
- **Manual Message Transmitter** to send arbitrary CAN frames on the fly.
- **Log Export & Playback** to download `.log` traces or upload historical files for IDS analysis.
