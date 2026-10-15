"""
BUSMASTER Simulation and Trace Engine.

Provides comprehensive support for BUSMASTER-compatible CAN bus simulation:
- Virtual ECU Node simulation with cyclic message scheduling and event handlers
- BUSMASTER log format (.log) export and real-time streaming
- BUSMASTER log parser and playback engine
- Interactive node control, fault injection, and manual frame transmission
"""

from __future__ import annotations

import datetime
import io
import logging
import math
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from can_security.can.interface import CANInterface, VirtualCANInterface
from can_security.can.message import CANMessageFactory
from can_security.core.enums import ECUType
from can_security.core.exceptions import CANInterfaceError
from can_security.core.models import CANMessage

logger = logging.getLogger(__name__)


# =============================================================================
# BUSMASTER Log Formatting & Parsing
# =============================================================================

@dataclass
class BusmasterTraceEntry:
    """A single trace entry in BUSMASTER format."""
    timestamp: float
    time_str: str
    channel: int
    direction: str  # "Tx" or "Rx"
    can_id: int
    can_id_hex: str
    frame_type: str  # "s" (standard) or "x" (extended)
    dlc: int
    data_bytes: list[int]
    data_hex: str
    node_name: str = "Unknown"

    def to_log_line(self) -> str:
        """Format as standard BUSMASTER log file line."""
        bytes_str = " ".join(f"{b:02X}" for b in self.data_bytes)
        return (
            f"{self.time_str} {self.frame_type} {self.channel} {self.direction} "
            f"0x{self.can_id:X} {self.frame_type} {self.dlc} {bytes_str}".strip()
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API/Dashboard display."""
        return {
            "timestamp": self.timestamp,
            "time_str": self.time_str,
            "channel": self.channel,
            "direction": self.direction,
            "can_id": self.can_id,
            "can_id_hex": self.can_id_hex,
            "frame_type": self.frame_type,
            "dlc": self.dlc,
            "data_hex": self.data_hex,
            "data_bytes": self.data_bytes,
            "node_name": self.node_name,
            "log_line": self.to_log_line(),
        }


class BusmasterLogWriter:
    """
    Writes CAN messages compliant with the ETAS/Bosch BUSMASTER log specification.
    """

    @staticmethod
    def generate_header(
        bus_speed: int = 500000,
        channel: int = 1,
        protocol: str = "CAN",
        start_time: datetime.datetime | None = None,
    ) -> list[str]:
        """Generate standard BUSMASTER log header."""
        dt = start_time or datetime.datetime.now()
        dt_str = dt.strftime("%d:%m:%Y %H:%M:%S:%f")[:23]
        return [
            "***BUSMASTER Log and Trace File***",
            f"***START DATE AND TIME {dt_str}***",
            f"***PROTOCOL {protocol}***",
            f"***BUS SPEED {bus_speed} bps***",
            f"***CHANNEL {channel}***",
            f"***START CHANNEL {channel}***",
            "***MODE SIMULATION***",
            "***FILTER NONE***",
            "***<Time><Tx/Rx><Channel><CAN ID><Type><DLC><DataBytes>***",
        ]

    @staticmethod
    def format_entry(
        msg: CANMessage,
        relative_start_time: float = 0.0,
        channel: int = 1,
        direction: str = "Tx",
        node_name: str = "",
    ) -> BusmasterTraceEntry:
        """Convert a CANMessage into a BusmasterTraceEntry."""
        rel_time = max(0.0, msg.timestamp - relative_start_time)
        hours = int(rel_time // 3600)
        minutes = int((rel_time % 3600) // 60)
        seconds = rel_time % 60
        sec_int = int(seconds)
        sec_frac = int(round((seconds - sec_int) * 10000))
        if sec_frac >= 10000:
            sec_int += 1
            sec_frac = 0
        time_str = f"{hours:02d}:{minutes:02d}:{sec_int:02d}.{sec_frac:04d}"

        frame_type = "x" if msg.can_id > 0x7FF else "s"
        data_bytes = list(msg.data)
        data_hex = " ".join(f"{b:02X}" for b in data_bytes)

        return BusmasterTraceEntry(
            timestamp=msg.timestamp,
            time_str=time_str,
            channel=channel,
            direction=direction,
            can_id=msg.can_id,
            can_id_hex=f"0x{msg.can_id:03X}",
            frame_type=frame_type,
            dlc=msg.dlc,
            data_bytes=data_bytes,
            data_hex=data_hex,
            node_name=node_name or msg.source_ecu.value,
        )

    @classmethod
    def export_to_string(
        cls,
        messages: list[CANMessage],
        bus_speed: int = 500000,
        channel: int = 1,
        start_time: float | None = None,
    ) -> str:
        """Export a list of CAN messages to a complete BUSMASTER log string."""
        first_time = start_time if start_time is not None else (messages[0].timestamp if messages else 0.0)
        lines = cls.generate_header(bus_speed=bus_speed, channel=channel)
        for msg in messages:
            entry = cls.format_entry(msg, relative_start_time=first_time, channel=channel)
            lines.append(entry.to_log_line())
        return "\n".join(lines) + "\n"

    @classmethod
    def export_to_file(
        cls,
        messages: list[CANMessage],
        file_path: str | Path,
        bus_speed: int = 500000,
        channel: int = 1,
    ) -> Path:
        """Export messages directly to a .log file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.export_to_string(messages, bus_speed=bus_speed, channel=channel)
        path.write_text(content, encoding="utf-8")
        return path


class BusmasterLogReader:
    """
    Parses BUSMASTER log files (.log) into CANMessage instances.
    """

    # Matches lines like:
    # 00:00:01.0250 s 1 Tx 0x100 s 8 01 02 03 04 05 06 07 08
    # or 12:34:56.7890 s 1 Rx 100 s 4 AA BB CC DD
    # or 1.2500 s 1 Tx 0x102 s 8 11 22 33 44
    _LINE_REGEX = re.compile(
        r"^(?P<time>(?:\d{1,2}:\d{1,2}:\d{1,2}\.\d+|\d+\.\d+|\d+))\s+"
        r"(?P<type_prefix>[sxSX])\s+"
        r"(?P<channel>\d+)\s+"
        r"(?P<dir>Tx|Rx|TX|RX)\s+"
        r"(?:0x)?(?P<id>[0-9a-fA-F]+)\s+"
        r"(?P<frame_type>[sxSX])\s+"
        r"(?P<dlc>\d+)"
        r"(?:\s+(?P<data>(?:[0-9a-fA-F]{2}\s*)*))?"
    )

    @classmethod
    def parse_time(cls, time_token: str) -> float:
        """Parse HH:MM:SS.mmmm or seconds float into seconds float."""
        if ":" in time_token:
            parts = time_token.split(":")
            if len(parts) == 3:
                h, m, s = parts
                return int(h) * 3600.0 + int(m) * 60.0 + float(s)
            elif len(parts) == 2:
                m, s = parts
                return int(m) * 60.0 + float(s)
        return float(time_token)

    @classmethod
    def parse_line(cls, line: str, base_timestamp: float = 0.0) -> CANMessage | None:
        """Parse a single line from a BUSMASTER log file."""
        clean = line.strip()
        if not clean or clean.startswith("***") or clean.startswith("#"):
            return None

        match = cls._LINE_REGEX.match(clean)
        if not match:
            # Fallback simple split parser for alternative BUSMASTER log layouts
            parts = clean.split()
            if len(parts) >= 6:
                try:
                    rel_sec = cls.parse_time(parts[0])
                    # Position 4 is usually the CAN ID (Time Type Ch Dir ID Type DLC Data...)
                    id_token = parts[4] if parts[3].upper() in ("TX", "RX") else parts[1]
                    dlc = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 8
                    data_tokens = parts[7:7+dlc] if len(parts) >= 7+dlc else []
                    if id_token:
                        can_id = int(id_token, 16)
                        data_bytes = bytes(int(b, 16) for b in data_tokens)
                        return CANMessage(
                            timestamp=base_timestamp + rel_sec,
                            can_id=can_id,
                            dlc=len(data_bytes),
                            data=data_bytes,
                            source_ecu=ECUType.UNKNOWN,
                        )
                except Exception:
                    pass
            return None

        gd = match.groupdict()
        rel_time = cls.parse_time(gd["time"])
        can_id = int(gd["id"], 16)
        dlc = int(gd["dlc"])
        raw_data = gd.get("data") or ""
        byte_tokens = raw_data.strip().split()
        data_bytes = bytes(int(b, 16) for b in byte_tokens[:dlc])

        if len(data_bytes) < dlc:
            # Pad with zeroes if fewer bytes present
            data_bytes = data_bytes.ljust(dlc, b"\x00")

        return CANMessage(
            timestamp=base_timestamp + rel_time,
            can_id=can_id,
            dlc=min(8, dlc),
            data=data_bytes[:8],
            source_ecu=ECUType.UNKNOWN,
        )

    @classmethod
    def parse_file(cls, file_path: str | Path, base_timestamp: float = 0.0) -> list[CANMessage]:
        """Parse all messages from a BUSMASTER .log file."""
        path = Path(file_path)
        if not path.exists():
            raise CANInterfaceError(f"BUSMASTER log file not found: {path}")

        messages: list[CANMessage] = []
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                msg = cls.parse_line(line, base_timestamp=base_timestamp)
                if msg is not None:
                    messages.append(msg)
        return messages


# =============================================================================
# BUSMASTER Node Simulation (Virtual ECUs)
# =============================================================================

@dataclass
class BusmasterMessageSchedule:
    """Configures a periodic message schedule for a BUSMASTER simulated node."""
    can_id: int
    period_ms: float
    dlc: int = 8
    generator_type: str = "counter"  # "counter", "engine", "brake", "steering", "random", "static"
    static_data: bytes = b"\x00" * 8
    enabled: bool = True
    last_tx_time: float = -1.0
    counter: int = 0

    def generate_payload(self, sim_time: float, vehicle_state: dict[str, Any]) -> bytes:
        """Generate payload for this transmission tick."""
        if self.generator_type == "counter":
            self.counter = (self.counter + 1) % 256
            return bytes([self.counter, (self.counter * 2) % 256, 0x00, 0x00, 0x00, 0x00, 0x00, self.counter])

        elif self.generator_type == "engine":
            # CAN ID 0x100: Engine speed (RPM) and throttle
            speed = vehicle_state.get("speed", 0.0)
            rpm = int(800 + speed * 45 + 100 * math.sin(sim_time))
            throttle = int(min(100, vehicle_state.get("pedal_position", 20.0)))
            rpm_h = (rpm >> 8) & 0xFF
            rpm_l = rpm & 0xFF
            self.counter = (self.counter + 1) % 16
            return bytes([rpm_h, rpm_l, throttle, 0x00, 0x1A, 0x2B, 0x3C, self.counter])

        elif self.generator_type == "brake":
            # CAN ID 0x102: Brake pressure, switch, ABS active
            brake_input = int(vehicle_state.get("brake_input", 0.0))
            switch = 1 if brake_input > 5 else 0
            abs_active = 1 if brake_input > 60 else 0
            self.counter = (self.counter + 1) % 16
            return bytes([brake_input, switch, abs_active, 0x00, 0x00, 0x00, 0x00, self.counter])

        elif self.generator_type == "steering":
            # CAN ID 0x103: Steering angle and rate
            angle = int(30 * math.sin(sim_time * 0.5) + 500)
            return bytes([(angle >> 8) & 0xFF, angle & 0xFF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00])

        elif self.generator_type == "speed":
            # CAN ID 0x101: Speed & odometer
            speed_val = int(vehicle_state.get("speed", 50.0))
            self.counter = (self.counter + 1) % 16
            return bytes([speed_val, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, self.counter])

        elif self.generator_type == "random":
            return bytes([random.randint(0, 255) for _ in range(self.dlc)])

        elif self.generator_type == "static":
            return self.static_data.ljust(self.dlc, b"\x00")[:self.dlc]

        return bytes(self.dlc)


class BusmasterNode:
    """
    Simulated CAN Node in BUSMASTER.

    Models an individual ECU on the bus with periodic message schedules,
    event callbacks, fault injection, and transmission counters.
    """

    def __init__(
        self,
        name: str,
        ecu_type: ECUType = ECUType.UNKNOWN,
        channel: int = 1,
        enabled: bool = True,
    ):
        self.name = name
        self.ecu_type = ecu_type
        self.channel = channel
        self.enabled = enabled
        self.schedules: list[BusmasterMessageSchedule] = []
        self.tx_count = 0
        self.rx_count = 0
        self.error_count = 0
        self.fault_mode: str = "none"  # "none", "burst", "corrupt", "bus_off"
        self.fault_expiry: float = 0.0

    def add_schedule(
        self,
        can_id: int,
        period_ms: float,
        dlc: int = 8,
        generator_type: str = "counter",
        static_data: bytes = b"\x00" * 8,
    ) -> BusmasterMessageSchedule:
        """Add a cyclic message schedule to this simulated node."""
        sched = BusmasterMessageSchedule(
            can_id=can_id,
            period_ms=period_ms,
            dlc=dlc,
            generator_type=generator_type,
            static_data=static_data,
        )
        self.schedules.append(sched)
        return sched

    def inject_fault(self, fault_type: str, duration: float = 5.0) -> None:
        """Inject a fault into this node (burst, corrupt, bus_off)."""
        self.fault_mode = fault_type
        self.fault_expiry = time.time() + duration
        logger.info(f"Node '{self.name}' injected with fault '{fault_type}' for {duration}s")

    def clear_fault(self) -> None:
        """Clear active fault."""
        self.fault_mode = "none"
        self.fault_expiry = 0.0

    def tick(
        self,
        sim_time: float,
        dt: float,
        vehicle_state: dict[str, Any],
    ) -> list[CANMessage]:
        """Generate scheduled messages for this time step."""
        if not self.enabled:
            return []

        # Check fault expiry
        if self.fault_mode != "none" and time.time() > self.fault_expiry:
            self.fault_mode = "none"

        # If Bus-Off fault, node cannot transmit
        if self.fault_mode == "bus_off":
            return []

        generated: list[CANMessage] = []

        for sched in self.schedules:
            if not sched.enabled:
                continue

            period_s = max(0.001, sched.period_ms / 1000.0)

            # Check if period has elapsed
            if sched.last_tx_time < 0 or (sim_time - sched.last_tx_time) >= (period_s - (dt * 0.5)):
                sched.last_tx_time = sim_time

                payload = sched.generate_payload(sim_time, vehicle_state)

                # Apply fault effects
                if self.fault_mode == "corrupt":
                    payload = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                    self.error_count += 1

                msg = CANMessageFactory.create(
                    can_id=sched.can_id,
                    data=payload,
                    source_ecu=self.ecu_type,
                    timestamp=sim_time,
                )
                generated.append(msg)
                self.tx_count += 1

                # If burst fault, inject multiple frames immediately
                if self.fault_mode == "burst":
                    for _ in range(3):
                        burst_msg = CANMessageFactory.create(
                            can_id=sched.can_id,
                            data=payload,
                            source_ecu=self.ecu_type,
                            timestamp=sim_time,
                        )
                        generated.append(burst_msg)
                        self.tx_count += 1

        return generated

    def transmit_single(
        self,
        can_id: int,
        data: bytes,
        sim_time: float | None = None,
    ) -> CANMessage:
        """Transmit an on-demand single-shot message from this node."""
        msg = CANMessageFactory.create(
            can_id=can_id,
            data=data,
            source_ecu=self.ecu_type,
            timestamp=sim_time if sim_time is not None else time.time(),
        )
        self.tx_count += 1
        return msg

    def to_dict(self) -> dict[str, Any]:
        """Convert node info to dictionary."""
        return {
            "name": self.name,
            "ecu_type": self.ecu_type.value,
            "channel": self.channel,
            "enabled": self.enabled,
            "tx_count": self.tx_count,
            "rx_count": self.rx_count,
            "error_count": self.error_count,
            "fault_mode": self.fault_mode,
            "schedules": [
                {
                    "can_id": s.can_id,
                    "can_id_hex": f"0x{s.can_id:03X}",
                    "period_ms": s.period_ms,
                    "dlc": s.dlc,
                    "generator_type": s.generator_type,
                    "enabled": s.enabled,
                }
                for s in self.schedules
            ],
        }


# =============================================================================
# BUSMASTER Simulator Engine
# =============================================================================

class BusmasterSimulator:
    """
    BUSMASTER-compatible CAN bus simulator and network orchestrator.

    Simulates an automotive CAN bus environment adhering to BUSMASTER specifications:
    - Multiple virtual nodes (ECUs) running periodic and event-triggered CAN traffic
    - Real-time circular BUSMASTER trace buffer
    - Trace export in native BUSMASTER .log format
    - Manual message transmission console
    - Fault & error frame simulation
    """

    def __init__(
        self,
        can_interface: CANInterface | None = None,
        bus_speed: int = 500000,
        channel: int = 1,
        max_trace_buffer: int = 2000,
    ):
        self.can_interface = can_interface or VirtualCANInterface()
        self.bus_speed = bus_speed
        self.channel = channel
        self.max_trace_buffer = max_trace_buffer

        self.nodes: dict[str, BusmasterNode] = {}
        self.trace_buffer: list[BusmasterTraceEntry] = []
        self._running = False
        self._sim_time = 0.0
        self._start_real_time = 0.0
        self._total_messages = 0

        # Shared vehicle physics for correlated signals
        self.vehicle_state: dict[str, Any] = {
            "speed": 60.0,
            "pedal_position": 25.0,
            "brake_input": 0.0,
            "engine_running": True,
        }

        # Initialize default standard automotive nodes
        self._setup_default_nodes()

    def _setup_default_nodes(self) -> None:
        """Setup standard default automotive nodes matching BUSMASTER configurations."""
        # 1. Engine ECU Node (0x100: Engine RPM/Throttle, 0x104: Engine Temp)
        engine_node = BusmasterNode("Engine_Node", ECUType.ENGINE, channel=self.channel)
        engine_node.add_schedule(0x100, period_ms=10, generator_type="engine")
        engine_node.add_schedule(0x104, period_ms=100, generator_type="counter")
        self.add_node(engine_node)

        # 2. Brake ECU Node (0x102: Brake Pressure & ABS)
        brake_node = BusmasterNode("Brake_Node", ECUType.BRAKE, channel=self.channel)
        brake_node.add_schedule(0x102, period_ms=10, generator_type="brake")
        self.add_node(brake_node)

        # 3. Steering ECU Node (0x103: Steering Angle)
        steering_node = BusmasterNode("Steering_Node", ECUType.STEERING, channel=self.channel)
        steering_node.add_schedule(0x103, period_ms=20, generator_type="steering")
        self.add_node(steering_node)

        # 4. Transmission Node (0x105: Gear & Shift status)
        trans_node = BusmasterNode("Transmission_Node", ECUType.TRANSMISSION, channel=self.channel)
        trans_node.add_schedule(0x105, period_ms=50, generator_type="counter")
        self.add_node(trans_node)

        # 5. Instrument Cluster Node (0x101: Speed/Odo, 0x107: Warning Flags)
        cluster_node = BusmasterNode("Cluster_Node", ECUType.INSTRUMENT_CLUSTER, channel=self.channel)
        cluster_node.add_schedule(0x101, period_ms=100, generator_type="speed")
        cluster_node.add_schedule(0x107, period_ms=200, generator_type="counter")
        self.add_node(cluster_node)

        # 6. Gateway / Diagnostics Tester Node (0x7DF: OBD-II Functional Query)
        gateway_node = BusmasterNode("Gateway_Tester_Node", ECUType.UNKNOWN, channel=self.channel)
        gateway_node.add_schedule(
            0x7DF, period_ms=500, dlc=8, generator_type="static",
            static_data=bytes([0x02, 0x01, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00])  # Query Vehicle Speed
        )
        self.add_node(gateway_node)

        # 7. Attacker / Test Injection Node (Disabled by default, ready for attack simulation)
        attacker_node = BusmasterNode("Attacker_Node", ECUType.UNKNOWN, channel=self.channel, enabled=False)
        attacker_node.add_schedule(0x102, period_ms=5, generator_type="random")  # High frequency brake spoofing
        self.add_node(attacker_node)

    def add_node(self, node: BusmasterNode) -> None:
        """Register a node in the simulator."""
        self.nodes[node.name] = node

    def get_node(self, name: str) -> BusmasterNode | None:
        """Retrieve a node by name."""
        return self.nodes.get(name)

    def toggle_node(self, name: str, enabled: bool | None = None) -> bool:
        """Toggle or set the enabled state of a node."""
        node = self.nodes.get(name)
        if not node:
            raise KeyError(f"Node '{name}' not found")
        if enabled is None:
            node.enabled = not node.enabled
        else:
            node.enabled = enabled
        return node.enabled

    def start(self) -> None:
        """Start the BUSMASTER simulation."""
        self._running = True
        self._sim_time = 0.0
        self._start_real_time = time.time()
        self.trace_buffer.clear()
        self.can_interface.start()
        logger.info("BUSMASTER Simulator started")

    def stop(self) -> None:
        """Stop the BUSMASTER simulation."""
        self._running = False
        self.can_interface.stop()
        logger.info(f"BUSMASTER Simulator stopped. Total messages: {self._total_messages}")

    def tick(self, current_time: float, dt: float) -> list[CANMessage]:
        """
        Advance simulation by dt seconds.
        Collects frames from all enabled nodes, logs to trace, and dispatches to CAN bus.
        """
        if not self._running:
            return []

        self._sim_time = current_time

        # Update dynamic vehicle state physics
        self._update_vehicle_state(dt)

        messages: list[CANMessage] = []

        for node_name, node in self.nodes.items():
            node_msgs = node.tick(current_time, dt, self.vehicle_state)
            for msg in node_msgs:
                messages.append(msg)
                self.can_interface.send(msg)

                # Record in BUSMASTER Trace Monitor
                entry = BusmasterLogWriter.format_entry(
                    msg,
                    relative_start_time=0.0,
                    channel=node.channel,
                    direction="Tx",
                    node_name=node_name,
                )
                self._record_trace(entry)

        self._total_messages += len(messages)
        return messages

    def _update_vehicle_state(self, dt: float) -> None:
        """Smooth vehicle physics variations."""
        t = self._sim_time
        # Gentle cyclic driving variation
        self.vehicle_state["speed"] = max(0.0, min(140.0, 65.0 + 35.0 * math.sin(t * 0.1)))
        self.vehicle_state["pedal_position"] = max(0.0, min(100.0, 30.0 + 20.0 * math.sin(t * 0.15)))
        self.vehicle_state["brake_input"] = 40.0 if math.sin(t * 0.1) < -0.8 else 0.0

    def transmit_manual(
        self,
        can_id: int,
        data: bytes,
        node_name: str = "Manual_Console",
        channel: int = 1,
    ) -> CANMessage:
        """Transmit a single manual CAN frame from BUSMASTER console."""
        msg = CANMessageFactory.create(
            can_id=can_id,
            data=data,
            source_ecu=ECUType.UNKNOWN,
            timestamp=self._sim_time or time.time(),
        )
        self.can_interface.send(msg)
        self._total_messages += 1

        entry = BusmasterLogWriter.format_entry(
            msg,
            relative_start_time=0.0,
            channel=channel,
            direction="Tx",
            node_name=node_name,
        )
        self._record_trace(entry)

        node = self.nodes.get(node_name)
        if node:
            node.tx_count += 1

        return msg

    def inject_fault(self, node_name: str, fault_type: str, duration: float = 5.0) -> None:
        """Inject fault into a specific node."""
        node = self.nodes.get(node_name)
        if not node:
            raise KeyError(f"Node '{node_name}' not found")
        node.inject_fault(fault_type, duration=duration)

    def _record_trace(self, entry: BusmasterTraceEntry) -> None:
        """Record entry into circular trace buffer."""
        self.trace_buffer.append(entry)
        if len(self.trace_buffer) > self.max_trace_buffer:
            self.trace_buffer.pop(0)

    def get_trace_buffer(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent trace entries as dicts."""
        return [entry.to_dict() for entry in self.trace_buffer[-limit:]]

    def export_log(self, file_path: str | Path | None = None) -> str:
        """
        Export current trace buffer as a standard BUSMASTER .log file.
        Returns the formatted string and optionally writes to file.
        """
        lines = BusmasterLogWriter.generate_header(
            bus_speed=self.bus_speed,
            channel=self.channel,
        )
        for entry in self.trace_buffer:
            lines.append(entry.to_log_line())
        content = "\n".join(lines) + "\n"

        if file_path:
            p = Path(file_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")

        return content

    def calculate_bus_load(self, time_window: float = 1.0) -> float:
        """
        Calculate bus load percentage over the given window.
        Standard CAN frame at 500kbps takes ~111 to ~130 bit times (nominal ~128 bits per 8-byte frame).
        """
        if not self._running or not self.trace_buffer:
            return 0.0

        now = self.trace_buffer[-1].timestamp
        recent_count = sum(1 for e in reversed(self.trace_buffer) if (now - e.timestamp) <= time_window)
        # 1 frame ~ 128 bits; bitrate = bus_speed bps
        bits_sent = recent_count * 128
        max_bits = self.bus_speed * time_window
        load = (bits_sent / max(1.0, max_bits)) * 100.0
        return min(100.0, round(load, 2))

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def total_messages(self) -> int:
        return self._total_messages

    def get_status(self) -> dict[str, Any]:
        """Summary status of BUSMASTER simulator."""
        return {
            "running": self._running,
            "bus_speed": self.bus_speed,
            "channel": self.channel,
            "total_messages": self._total_messages,
            "trace_buffer_size": len(self.trace_buffer),
            "bus_load_percent": self.calculate_bus_load(),
            "nodes_count": len(self.nodes),
            "nodes": [node.to_dict() for node in self.nodes.values()],
        }


# =============================================================================
# BUSMASTER Playback Engine
# =============================================================================

class BusmasterPlaybackEngine:
    """
    Replays a BUSMASTER log file (.log) through the CAN bus interface or security pipeline.
    """

    def __init__(
        self,
        file_path: str | Path,
        real_time: bool = True,
        playback_speed: float = 1.0,
    ):
        self.file_path = Path(file_path)
        self.real_time = real_time
        self.playback_speed = max(0.1, playback_speed)
        self._active = False
        self._messages: list[CANMessage] = []
        self._index = 0
        self._start_time = 0.0
        self._first_msg_time = 0.0

    def start(self) -> None:
        """Parse log file and initialize playback."""
        if not self.file_path.exists():
            raise CANInterfaceError(f"Log file not found: {self.file_path}")

        self._messages = BusmasterLogReader.parse_file(self.file_path)
        if not self._messages:
            logger.warning(f"No valid CAN messages found in BUSMASTER log: {self.file_path}")

        self._index = 0
        self._active = True
        self._start_time = time.time()
        self._first_msg_time = self._messages[0].timestamp if self._messages else 0.0
        logger.info(f"BUSMASTER playback started: {len(self._messages)} frames")

    def stop(self) -> None:
        """Stop playback."""
        self._active = False
        logger.info("BUSMASTER playback stopped")

    def receive(self, timeout: float | None = None) -> CANMessage | None:
        """Receive the next message from the playback stream."""
        if not self._active or self._index >= len(self._messages):
            self._active = False
            return None

        msg = self._messages[self._index]
        self._index += 1

        if self.real_time:
            elapsed_log = (msg.timestamp - self._first_msg_time) / self.playback_speed
            elapsed_real = time.time() - self._start_time
            sleep_time = elapsed_log - elapsed_real
            if sleep_time > 0:
                time.sleep(min(sleep_time, timeout if timeout else 0.5))

        return msg

    def is_active(self) -> bool:
        return self._active

    @property
    def total_messages(self) -> int:
        return len(self._messages)

    @property
    def progress_percent(self) -> float:
        if not self._messages:
            return 100.0
        return round((self._index / len(self._messages)) * 100.0, 1)
