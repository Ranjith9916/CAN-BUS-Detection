"""
FastAPI backend for the CAN Security Framework.

Provides REST API + WebSocket endpoints for the dashboard.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
import tempfile
from pydantic import BaseModel

from can_security.attacks.simulator import AttackSimulator
from can_security.authentication.freshness import FreshnessManager
from can_security.authentication.hmac_auth import HMACAuthenticator
from can_security.authentication.key_manager import KeyManager
from can_security.can.busmaster import (
    BusmasterLogReader,
    BusmasterLogWriter,
    BusmasterPlaybackEngine,
    BusmasterSimulator,
)
from can_security.can.collector import CANCollector
from can_security.can.interface import VirtualCANInterface
from can_security.can.playback import LogPlaybackEngine
from can_security.can.simulator import VehicleSimulator
from can_security.core.config import load_config
from can_security.core.enums import AttackType, AuthStatus, FreshnessStatus
from can_security.database.database import DatabaseManager
from can_security.decision.engine import SecurityDecisionEngine
from can_security.detection.rules import RuleEngine
from can_security.features.extractor import FeatureExtractor

logger = logging.getLogger(__name__)


# =============================================================================
# Pydantic Schemas
# =============================================================================

class StatusResponse(BaseModel):
    status: str
    mode: str
    version: str
    uptime_seconds: float
    simulation_running: bool
    analysis_running: bool
    attack_running: bool
    busmaster_running: bool = False
    total_messages: int
    total_alerts: int
    total_attacks_detected: int


class SimulationStartRequest(BaseModel):
    duration: int = 30
    seed: int | None = None
    scenario: str = "normal_driving"


class AttackStartRequest(BaseModel):
    attack_type: str
    target_id: str = "0x102"
    duration: int = 10
    rate: int = 20


class BusmasterStartRequest(BaseModel):
    duration: int = 60
    bus_speed: int = 500000


class BusmasterTransmitRequest(BaseModel):
    can_id: str = "0x102"
    data: str = "0102030405060708"
    node_name: str = "Manual_Console"
    channel: int = 1


class BusmasterFaultRequest(BaseModel):
    node_name: str = "Brake_Node"
    fault_type: str = "burst"  # burst, corrupt, bus_off
    duration: float = 5.0


class BusmasterToggleNodeRequest(BaseModel):
    node_name: str
    enabled: bool | None = None


class MetricsResponse(BaseModel):
    messages_per_second: float
    processing_latency_ms: float
    cpu_percent: float
    memory_mb: float
    total_messages: int
    total_alerts: int


# =============================================================================
# Application State
# =============================================================================

class AppState:
    """Shared application state across all routes."""

    def __init__(self):
        self.config = load_config()
        self.start_time = time.time()

        # Core components
        self.can_interface = VirtualCANInterface(self.config.can.buffer_size)
        self.simulator = VehicleSimulator(self.config)
        self.playback_engine = None
        self.collector = CANCollector(self.can_interface)
        self.rule_engine = RuleEngine(
            self.config.can_id_definitions, self.config.detection_rules
        )
        self.feature_extractor = FeatureExtractor(
            self.config.feature_extraction.window_size,
            self.config.feature_extraction.window_overlap,
        )
        self.decision_engine = SecurityDecisionEngine(
            risk_thresholds={
                "normal": self.config.detection.risk_thresholds.normal,
                "low": self.config.detection.risk_thresholds.low,
                "medium": self.config.detection.risk_thresholds.medium,
                "high": self.config.detection.risk_thresholds.high,
                "critical": self.config.detection.risk_thresholds.critical,
            }
        )
        self.attack_sim = AttackSimulator(seed=self.config.simulation.seed)
        self.freshness_mgr = FreshnessManager(
            max_counter_jump=self.config.freshness.max_counter_jump
        )

        # Key management
        self.key_mgr = KeyManager()
        self.key_mgr.generate_key("simulation", version=1)
        self.authenticator = HMACAuthenticator(
            self.key_mgr.get_key("simulation"),
            key_id="simulation",
            key_version=1,
            tag_length=self.config.authentication.tag_length_bytes,
        )

        # Database
        self.db = DatabaseManager(self.config.database.url)
        self.db.initialize()

        # ML detector (loaded if available)
        self.ml_detector = None
        self._try_load_ml()

        # BUSMASTER Simulator
        self.busmaster_sim = BusmasterSimulator(
            can_interface=self.can_interface,
            bus_speed=self.config.can.bitrate,
        )
        self.busmaster_running = False
        self.busmaster_task: asyncio.Task | None = None

        # Runtime state
        self.simulation_running = False
        self.simulation_task: asyncio.Task | None = None
        self.analysis_running = False
        self.analysis_task: asyncio.Task | None = None
        self.total_messages = 0
        self.total_alerts = 0
        self.total_attacks = 0
        self.recent_events: list[dict] = []
        self.recent_alerts: list[dict] = []
        self.recent_messages: list[dict] = []
        self.ws_clients: list[WebSocket] = []

    def _try_load_ml(self):
        model_path = Path(self.config.ml.model_path) / "random_forest.joblib"
        if model_path.exists():
            try:
                from can_security.detection.ml_detector import RandomForestDetector
                self.ml_detector = RandomForestDetector()
                self.ml_detector.load(str(model_path))
                logger.info("ML model loaded")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")


# =============================================================================
# FastAPI App
# =============================================================================

state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    logger.info("CAN Security Framework API starting")
    yield
    if state.simulation_running:
        state.simulation_running = False
        state.simulator.stop()
    if state.busmaster_running:
        state.busmaster_running = False
        state.busmaster_sim.stop()
    if state.analysis_running:
        state.analysis_running = False
        if state.playback_engine:
            state.playback_engine.stop()
    logger.info("CAN Security Framework API stopped")


app = FastAPI(
    title="CAN Security Framework API",
    description="Intrusion Detection and Message Authentication for CAN Bus Networks",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=state.config.api.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Routes
# =============================================================================

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "mode": "SIMULATION",
        "version": state.config.version,
        "uptime": round(time.time() - state.start_time, 1),
    }


@app.get("/api/status", response_model=StatusResponse)
async def get_status():
    return StatusResponse(
        status="running",
        mode=state.config.mode,
        version=state.config.version,
        uptime_seconds=round(time.time() - state.start_time, 1),
        simulation_running=state.simulation_running,
        analysis_running=state.analysis_running,
        attack_running=state.attack_sim.is_running,
        busmaster_running=state.busmaster_running,
        total_messages=state.total_messages,
        total_alerts=state.total_alerts,
        total_attacks_detected=state.total_attacks,
    )


@app.get("/api/can/messages")
async def get_messages(limit: int = 50):
    return {"messages": state.recent_messages[-limit:]}


@app.get("/api/security/events")
async def get_events(limit: int = 50):
    return {"events": state.recent_events[-limit:]}


@app.get("/api/security/alerts")
async def get_alerts(limit: int = 50):
    return {"alerts": state.recent_alerts[-limit:]}


@app.get("/api/metrics")
async def get_metrics():
    process = psutil.Process()
    return MetricsResponse(
        messages_per_second=state.total_messages / max(1, time.time() - state.start_time),
        processing_latency_ms=0.0,
        cpu_percent=process.cpu_percent(),
        memory_mb=process.memory_info().rss / (1024 * 1024),
        total_messages=state.total_messages,
        total_alerts=state.total_alerts,
    )


@app.get("/api/models")
async def get_models():
    if state.ml_detector and state.ml_detector.is_trained:
        return {
            "models": [{
                "name": state.ml_detector.name,
                "type": state.ml_detector.detector_type.value,
                "trained": True,
            }]
        }
    return {"models": [], "message": "No ML model loaded. Run 'python -m can_security train' first."}


@app.get("/api/authentication/status")
async def get_auth_status():
    keys = state.key_mgr.list_keys()
    return {
        "enabled": state.config.authentication.enabled,
        "algorithm": state.config.authentication.algorithm,
        "keys_loaded": len(keys),
        "keys": [
            {"key_id": k.key_id, "version": k.version, "algorithm": k.algorithm}
            for k in keys
        ],
    }


@app.get("/api/config")
async def get_config():
    return {
        "mode": state.config.mode,
        "can_interface": state.config.can.interface,
        "can_ids": len(state.config.can_id_definitions),
        "detection_rules": len(state.config.detection_rules),
        "ml_model_type": state.config.ml.model_type,
        "anomaly_threshold": state.config.detection.anomaly_threshold,
        "auth_enabled": state.config.authentication.enabled,
        "freshness_enabled": state.config.freshness.enabled,
    }


@app.post("/api/simulation/start")
async def start_simulation(req: SimulationStartRequest):
    if state.simulation_running:
        return {"status": "already_running"}

    if req.seed is not None:
        state.config.simulation.seed = req.seed

    state.simulation_running = True
    state.simulator = VehicleSimulator(state.config)
    state.simulator.start()
    state.collector.start()
    state.can_interface.start()

    state.simulation_task = asyncio.create_task(
        _run_simulation_loop(req.duration)
    )
    return {"status": "started", "duration": req.duration}


@app.post("/api/simulation/stop")
async def stop_simulation():
    state.simulation_running = False
    if state.simulation_task:
        state.simulation_task.cancel()
    state.simulator.stop()
    state.collector.stop()
    return {"status": "stopped", "total_messages": state.total_messages}


@app.post("/api/analysis/upload")
async def upload_log(file: UploadFile = File(...), speed: float = 1.0):
    if state.analysis_running:
        return {"error": "Analysis is already running"}
    if state.simulation_running:
        return {"error": "Cannot run analysis while simulation is running"}

    # Save to temp file
    suffix = Path(file.filename).suffix
    fd, temp_path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, 'wb') as f:
        content = await file.read()
        f.write(content)

    state.analysis_running = True
    state.collector.start()
    
    state.playback_engine = LogPlaybackEngine(
        file_path=temp_path, 
        real_time=True if speed <= 1.0 else False,
        playback_speed=speed
    )
    state.playback_engine.start()

    state.analysis_task = asyncio.create_task(_run_playback_loop(temp_path))
    return {"status": "started", "file": file.filename}


@app.post("/api/analysis/stop")
async def stop_analysis():
    state.analysis_running = False
    if state.analysis_task:
        state.analysis_task.cancel()
    if state.playback_engine:
        state.playback_engine.stop()
    state.collector.stop()
    return {"status": "stopped", "total_messages": state.total_messages}


@app.post("/api/attacks/start")
async def start_attack(req: AttackStartRequest):
    if not state.simulation_running:
        return {"error": "Start simulation first"}

    try:
        attack_type = AttackType(req.attack_type.upper())
    except ValueError:
        return {"error": f"Unknown attack type: {req.attack_type}"}

    target_id = int(req.target_id, 16) if req.target_id.startswith("0x") else int(req.target_id)
    state.attack_sim.start_attack(attack_type, target_id=target_id, rate=req.rate)
    return {"status": "attack_started", "type": req.attack_type, "mode": "SIMULATION"}


@app.post("/api/attacks/stop")
async def stop_attack():
    summary = state.attack_sim.stop_attack()
    return {"status": "attack_stopped", "summary": summary}


# =============================================================================
# BUSMASTER Simulator Endpoints
# =============================================================================

@app.get("/api/busmaster/status")
async def get_busmaster_status():
    """Get the current status of the BUSMASTER simulator."""
    return state.busmaster_sim.get_status()


@app.get("/api/busmaster/nodes")
async def get_busmaster_nodes():
    """Get all configured BUSMASTER simulated nodes."""
    return {"nodes": [node.to_dict() for node in state.busmaster_sim.nodes.values()]}


@app.post("/api/busmaster/nodes/toggle")
async def toggle_busmaster_node(req: BusmasterToggleNodeRequest):
    """Enable or disable a specific BUSMASTER node."""
    try:
        enabled = state.busmaster_sim.toggle_node(req.node_name, req.enabled)
        return {"status": "success", "node_name": req.node_name, "enabled": enabled}
    except KeyError:
        return {"error": f"Node '{req.node_name}' not found"}


@app.post("/api/busmaster/start")
async def start_busmaster_simulation(req: BusmasterStartRequest):
    """Start the BUSMASTER simulation engine."""
    if state.busmaster_running:
        return {"status": "already_running"}
    if state.simulation_running:
        return {"error": "Standard vehicle simulation is running. Please stop it first."}
    if state.analysis_running:
        return {"error": "Log playback analysis is running. Please stop it first."}

    state.busmaster_running = True
    state.busmaster_sim.bus_speed = req.bus_speed
    state.busmaster_sim.start()
    state.collector.start()

    state.busmaster_task = asyncio.create_task(_run_busmaster_loop(req.duration))
    return {
        "status": "started",
        "duration": req.duration,
        "bus_speed": req.bus_speed,
        "channel": state.busmaster_sim.channel,
    }


@app.post("/api/busmaster/stop")
async def stop_busmaster_simulation():
    """Stop the BUSMASTER simulation engine."""
    state.busmaster_running = False
    if state.busmaster_task:
        state.busmaster_task.cancel()
    state.busmaster_sim.stop()
    state.collector.stop()
    return {"status": "stopped", "total_messages": state.busmaster_sim.total_messages}


@app.post("/api/busmaster/transmit")
async def transmit_busmaster_message(req: BusmasterTransmitRequest):
    """Transmit a manual single-shot frame via BUSMASTER console."""
    can_id = int(req.can_id, 16) if req.can_id.startswith("0x") else int(req.can_id)
    clean_hex = req.data.replace(" ", "").replace("0x", "")
    data_bytes = bytes.fromhex(clean_hex) if clean_hex else b""
    data_bytes = data_bytes[:8]

    msg = state.busmaster_sim.transmit_manual(
        can_id=can_id,
        data=data_bytes,
        node_name=req.node_name,
        channel=req.channel,
    )
    await _process_single_message(msg)
    return {"status": "transmitted", "message": msg.to_dict()}


@app.post("/api/busmaster/fault")
async def inject_busmaster_fault(req: BusmasterFaultRequest):
    """Inject a fault into a simulated BUSMASTER node."""
    try:
        state.busmaster_sim.inject_fault(req.node_name, req.fault_type, duration=req.duration)
        return {
            "status": "fault_injected",
            "node": req.node_name,
            "fault_type": req.fault_type,
            "duration": req.duration,
        }
    except KeyError:
        return {"error": f"Node '{req.node_name}' not found"}


@app.get("/api/busmaster/trace")
async def get_busmaster_trace(limit: int = 100):
    """Retrieve recent BUSMASTER trace entries."""
    return {"trace": state.busmaster_sim.get_trace_buffer(limit=limit)}


@app.get("/api/busmaster/export-log")
async def export_busmaster_log():
    """Download BUSMASTER formatted log file."""
    content = state.busmaster_sim.export_log()
    return PlainTextResponse(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=busmaster_trace.log"},
    )


@app.post("/api/busmaster/upload-log")
async def upload_busmaster_log(file: UploadFile = File(...), speed: float = 1.0):
    """Upload and replay a BUSMASTER .log file through the IDS."""
    if state.analysis_running or state.busmaster_running or state.simulation_running:
        return {"error": "Another simulation or analysis is already running"}

    suffix = Path(file.filename).suffix
    fd, temp_path = tempfile.mkstemp(suffix=suffix or ".log")
    with os.fdopen(fd, 'wb') as f:
        content = await file.read()
        f.write(content)

    state.analysis_running = True
    state.collector.start()

    state.playback_engine = BusmasterPlaybackEngine(
        file_path=temp_path,
        real_time=True if speed <= 1.0 else False,
        playback_speed=speed,
    )
    state.playback_engine.start()

    state.analysis_task = asyncio.create_task(_run_playback_loop(temp_path))
    return {
        "status": "started",
        "file": file.filename,
        "total_messages": state.playback_engine.total_messages,
    }


# =============================================================================
# WebSocket for Real-Time Updates
# =============================================================================

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    state.ws_clients.append(ws)
    try:
        while True:
            # Send periodic updates
            update = {
                "type": "status",
                "simulation_running": state.simulation_running,
                "analysis_running": state.analysis_running,
                "attack_running": state.attack_sim.is_running,
                "busmaster_running": state.busmaster_running,
                "busmaster_load": state.busmaster_sim.calculate_bus_load() if state.busmaster_running else 0.0,
                "total_messages": state.total_messages,
                "total_alerts": state.total_alerts,
                "total_attacks": state.total_attacks,
                "messages_per_second": round(
                    state.total_messages / max(1, time.time() - state.start_time), 1
                ),
                "recent_events": state.recent_events[-5:],
                "recent_alerts": state.recent_alerts[-5:],
            }
            await ws.send_json(update)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        state.ws_clients.remove(ws)
    except Exception:
        if ws in state.ws_clients:
            state.ws_clients.remove(ws)


# =============================================================================
# Simulation Loop
# =============================================================================

async def _run_simulation_loop(duration: int):
    """Background task running the simulation + detection pipeline."""
    import numpy as np

    tick_dt = 1.0 / state.config.simulation.tick_rate_hz
    sim_time = 0.0
    start_real = time.time()

    try:
        while state.simulation_running and sim_time < duration:
            # Generate vehicle traffic
            messages = state.simulator.tick(sim_time, tick_dt)

            # Generate attack traffic if active
            if state.attack_sim.is_running:
                attack_msgs = state.attack_sim.generate_attack_messages(sim_time)
                messages.extend(attack_msgs)

            # Process each message
            for msg in messages:
                await _process_single_message(msg)

            sim_time += tick_dt

            # Yield to event loop every tick to maintain API responsiveness
            await asyncio.sleep(0)

    except asyncio.CancelledError:
        pass
    finally:
        state.simulation_running = False
        state.simulator.stop()
        logger.info(
            f"Simulation ended: {state.total_messages} messages, "
            f"{state.total_alerts} alerts, {state.total_attacks} attacks detected"
        )


async def _run_playback_loop(temp_path: str):
    """Background task for reading from a log file."""
    try:
        while state.analysis_running:
            # Receive from the playback engine
            msg = state.playback_engine.receive(timeout=0.1)
            if msg:
                await _process_single_message(msg)
            elif not state.playback_engine.is_active():
                # End of file
                break
            else:
                await asyncio.sleep(0.01)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Playback loop error: {e}")
    finally:
        state.analysis_running = False
        if state.playback_engine:
            state.playback_engine.stop()
        
        # Clean up temp file
        try:
            os.remove(temp_path)
        except Exception:
            pass
        logger.info("Log playback analysis ended")


async def _run_busmaster_loop(duration: int):
    """Background task running the BUSMASTER simulation + IDS pipeline."""
    tick_dt = 1.0 / state.config.simulation.tick_rate_hz
    sim_time = 0.0
    try:
        while state.busmaster_running and sim_time < duration:
            messages = state.busmaster_sim.tick(sim_time, tick_dt)
            for msg in messages:
                await _process_single_message(msg)
            sim_time += tick_dt
            await asyncio.sleep(0)
    except asyncio.CancelledError:
        pass
    finally:
        state.busmaster_running = False
        state.busmaster_sim.stop()
        logger.info(
            f"BUSMASTER simulation finished: {state.busmaster_sim.total_messages} messages"
        )


async def _process_single_message(msg):
    import numpy as np
    
    state.total_messages += 1
    state.collector.process_message(msg)

    # Store recent for API
    msg_dict = msg.to_dict()
    state.recent_messages.append(msg_dict)
    if len(state.recent_messages) > 500:
        state.recent_messages = state.recent_messages[-500:]

    # Rule-based detection
    rule_evidence = state.rule_engine.evaluate(msg)

    # Freshness check
    freshness_result = None
    if state.config.freshness.enabled and msg.sequence_counter is not None:
        freshness_result = state.freshness_mgr.check(
            msg.can_id, msg.sequence_counter
        )

    # ML detection (if model loaded)
    ml_prediction = None
    if state.ml_detector and state.ml_detector.is_trained:
        fv = state.feature_extractor.add_message(msg)
        if fv is not None:
            features = np.array(fv.to_array())
            ml_prediction = state.ml_detector.predict(features)

    # Security decision (only if there's evidence)
    if rule_evidence or ml_prediction or (
        freshness_result and freshness_result.status != FreshnessStatus.FRESH
    ):
        event = state.decision_engine.evaluate(
            msg,
            rule_evidence=rule_evidence,
            ml_prediction=ml_prediction,
            freshness_result=freshness_result,
        )
        event_dict = event.to_dict()
        state.recent_events.append(event_dict)
        if len(state.recent_events) > 200:
            state.recent_events = state.recent_events[-200:]

        # Store in database asynchronously to prevent blocking
        asyncio.create_task(asyncio.to_thread(state.db.store_event, event_dict))

        # Generate alert if warranted
        alert = state.decision_engine.create_alert(event)
        if alert:
            state.total_alerts += 1
            if event.attack_type != AttackType.NONE:
                state.total_attacks += 1
            alert_dict = alert.to_dict()
            state.recent_alerts.append(alert_dict)
            if len(state.recent_alerts) > 100:
                state.recent_alerts = state.recent_alerts[-100:]
            asyncio.create_task(asyncio.to_thread(state.db.store_alert, alert_dict))

            # Broadcast to WebSocket clients
            for ws in list(state.ws_clients):
                try:
                    await ws.send_json({
                        "type": "alert",
                        "alert": alert_dict,
                    })
                except Exception:
                    pass


def create_app() -> FastAPI:
    """Factory for creating the app (useful for testing)."""
    return app
