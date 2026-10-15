"""
Unit tests for BUSMASTER simulator and log engine.
"""

import tempfile
from pathlib import Path

import pytest

from can_security.can.busmaster import (
    BusmasterLogReader,
    BusmasterLogWriter,
    BusmasterNode,
    BusmasterPlaybackEngine,
    BusmasterSimulator,
)
from can_security.can.interface import VirtualCANInterface
from can_security.can.message import CANMessageFactory
from can_security.core.enums import ECUType
from can_security.core.models import CANMessage


def test_busmaster_log_writer_header():
    """Verify standard BUSMASTER log header format."""
    header = BusmasterLogWriter.generate_header(bus_speed=500000, channel=1)
    assert len(header) >= 8
    assert "***BUSMASTER Log and Trace File***" in header[0]
    assert any("500000 bps" in line for line in header)
    assert any("PROTOCOL CAN" in line for line in header)


def test_busmaster_log_writer_and_reader_roundtrip():
    """Verify that writing messages to BUSMASTER format and reading them back preserves data."""
    msgs = [
        CANMessageFactory.create(0x100, b"\x01\x02\x03\x04\x05\x06\x07\x08", timestamp=1.0),
        CANMessageFactory.create(0x102, b"\xAA\xBB\xCC\xDD", timestamp=1.05),
        CANMessageFactory.create(0x7DF, b"\x02\x01\x0D\x00\x00\x00\x00\x00", timestamp=1.20),
    ]

    log_str = BusmasterLogWriter.export_to_string(msgs, bus_speed=500000, start_time=1.0)
    assert "***BUSMASTER Log and Trace File***" in log_str
    assert "0x100" in log_str
    assert "0x102" in log_str

    with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
        f.write(log_str)
        f_path = Path(f.name)

    try:
        parsed_msgs = BusmasterLogReader.parse_file(f_path, base_timestamp=0.0)
        assert len(parsed_msgs) == 3
        assert parsed_msgs[0].can_id == 0x100
        assert parsed_msgs[0].data == b"\x01\x02\x03\x04\x05\x06\x07\x08"
        assert parsed_msgs[1].can_id == 0x102
        assert parsed_msgs[1].data == b"\xAA\xBB\xCC\xDD"
        assert parsed_msgs[2].can_id == 0x7DF
    finally:
        f_path.unlink(missing_ok=True)


def test_busmaster_node_scheduling():
    """Verify BusmasterNode schedule generation and payload generators."""
    node = BusmasterNode("Test_Engine", ECUType.ENGINE)
    sched = node.add_schedule(0x100, period_ms=10, generator_type="engine")

    state = {"speed": 50.0, "pedal_position": 30.0, "brake_input": 0.0}
    msgs1 = node.tick(sim_time=0.0, dt=0.01, vehicle_state=state)
    assert len(msgs1) == 1
    assert msgs1[0].can_id == 0x100
    assert len(msgs1[0].data) == 8

    # Tick too soon (<10ms)
    msgs2 = node.tick(sim_time=0.005, dt=0.005, vehicle_state=state)
    assert len(msgs2) == 0

    # Tick after period (at 10ms)
    msgs3 = node.tick(sim_time=0.011, dt=0.006, vehicle_state=state)
    assert len(msgs3) == 1


def test_busmaster_node_fault_injection():
    """Verify fault modes like burst, corrupt, and bus-off."""
    node = BusmasterNode("Faulty_Node", ECUType.BRAKE)
    node.add_schedule(0x102, period_ms=10, generator_type="brake")
    state = {"brake_input": 20.0}

    # Corrupt fault
    node.inject_fault("corrupt", duration=1.0)
    msgs = node.tick(sim_time=0.0, dt=0.01, vehicle_state=state)
    assert len(msgs) == 1
    assert msgs[0].data == bytes([0xFF] * 8)

    # Bus-Off fault
    node.inject_fault("bus_off", duration=1.0)
    msgs = node.tick(sim_time=0.02, dt=0.01, vehicle_state=state)
    assert len(msgs) == 0

    # Clear fault
    node.clear_fault()
    msgs = node.tick(sim_time=0.04, dt=0.01, vehicle_state=state)
    assert len(msgs) == 1


def test_busmaster_simulator_lifecycle():
    """Verify full BusmasterSimulator start, tick, transmit, and export."""
    vcan = VirtualCANInterface()
    sim = BusmasterSimulator(can_interface=vcan)

    assert len(sim.nodes) >= 6
    assert "Engine_Node" in sim.nodes
    assert "Brake_Node" in sim.nodes
    assert "Gateway_Tester_Node" in sim.nodes

    sim.start()
    assert sim.is_running

    # Run for 0.1s (10 ticks at dt=0.01)
    all_msgs = []
    for step in range(10):
        t = step * 0.01
        batch = sim.tick(t, 0.01)
        all_msgs.extend(batch)

    assert len(all_msgs) > 0
    assert sim.total_messages == len(all_msgs)

    # Manual transmit
    manual_msg = sim.transmit_manual(0x222, b"\x12\x34\x56\x78", node_name="Tester")
    assert manual_msg.can_id == 0x222
    assert sim.total_messages == len(all_msgs) + 1

    # Check trace buffer
    trace = sim.get_trace_buffer(limit=50)
    assert len(trace) > 0
    assert any(entry["can_id"] == 0x222 for entry in trace)

    # Export log
    log_content = sim.export_log()
    assert "***BUSMASTER Log and Trace File***" in log_content
    assert "0x222" in log_content

    # Toggle node
    sim.toggle_node("Engine_Node", enabled=False)
    assert not sim.nodes["Engine_Node"].enabled

    # Calculate bus load
    load = sim.calculate_bus_load()
    assert 0.0 <= load <= 100.0

    sim.stop()
    assert not sim.is_running


def test_busmaster_playback_engine():
    """Verify BusmasterPlaybackEngine replays messages accurately."""
    msgs = [
        CANMessageFactory.create(0x100, b"\x01\x02\x03\x04\x05\x06\x07\x08", timestamp=10.0),
        CANMessageFactory.create(0x102, b"\xAA\xBB\xCC\xDD", timestamp=10.01),
    ]

    with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
        f.write(BusmasterLogWriter.export_to_string(msgs, start_time=10.0))
        f_path = Path(f.name)

    try:
        engine = BusmasterPlaybackEngine(f_path, real_time=False)
        engine.start()
        assert engine.is_active()

        m1 = engine.receive()
        assert m1 is not None
        assert m1.can_id == 0x100

        m2 = engine.receive()
        assert m2 is not None
        assert m2.can_id == 0x102

        m3 = engine.receive()
        assert m3 is None
        assert not engine.is_active()
    finally:
        f_path.unlink(missing_ok=True)
