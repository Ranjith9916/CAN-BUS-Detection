"""
Integration tests for BUSMASTER API endpoints.
"""

from fastapi.testclient import TestClient
import pytest

from can_security.api.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_busmaster_status_endpoint(client):
    """Test GET /api/busmaster/status."""
    response = client.get("/api/busmaster/status")
    assert response.status_code == 200
    data = response.json()
    assert "running" in data
    assert "bus_speed" in data
    assert "nodes" in data
    assert len(data["nodes"]) >= 6


def test_busmaster_nodes_endpoint(client):
    """Test GET /api/busmaster/nodes."""
    response = client.get("/api/busmaster/nodes")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    node_names = [n["name"] for n in data["nodes"]]
    assert "Engine_Node" in node_names
    assert "Brake_Node" in node_names


def test_busmaster_toggle_node_endpoint(client):
    """Test POST /api/busmaster/nodes/toggle."""
    response = client.post(
        "/api/busmaster/nodes/toggle",
        json={"node_name": "Engine_Node", "enabled": False},
    )
    assert response.status_code == 200
    assert response.json()["enabled"] is False

    # Toggle back to enabled
    response2 = client.post(
        "/api/busmaster/nodes/toggle",
        json={"node_name": "Engine_Node", "enabled": True},
    )
    assert response2.status_code == 200
    assert response2.json()["enabled"] is True


def test_busmaster_manual_transmit(client):
    """Test POST /api/busmaster/transmit."""
    response = client.post(
        "/api/busmaster/transmit",
        json={
            "can_id": "0x102",
            "data": "1122334455667788",
            "node_name": "Test_Console",
            "channel": 1,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "transmitted"
    assert data["message"]["can_id_hex"] == "0x102"


def test_busmaster_trace_and_export(client):
    """Test trace retrieval and log export."""
    # Transmit a frame
    client.post(
        "/api/busmaster/transmit",
        json={"can_id": "0x105", "data": "AABBCCDD", "node_name": "Console"},
    )

    # Get trace
    trace_res = client.get("/api/busmaster/trace?limit=10")
    assert trace_res.status_code == 200
    traces = trace_res.json()["trace"]
    assert len(traces) > 0
    assert any(t["can_id"] == 0x105 for t in traces)

    # Export log
    export_res = client.get("/api/busmaster/export-log")
    assert export_res.status_code == 200
    assert "***BUSMASTER Log and Trace File***" in export_res.text
    assert "0x105" in export_res.text


def test_busmaster_fault_injection(client):
    """Test POST /api/busmaster/fault."""
    response = client.post(
        "/api/busmaster/fault",
        json={"node_name": "Brake_Node", "fault_type": "burst", "duration": 2.0},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "fault_injected"
