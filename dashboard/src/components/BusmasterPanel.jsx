import { useState, useEffect, useRef } from 'react'

export default function BusmasterPanel({ apiBase = 'http://localhost:8000' }) {
  const [status, setStatus] = useState(null)
  const [nodes, setNodes] = useState([])
  const [trace, setTrace] = useState([])
  const [running, setRunning] = useState(false)
  const [busSpeed, setBusSpeed] = useState(500000)
  const [duration, setDuration] = useState(60)
  const [filterId, setFilterId] = useState('')
  const [filterNode, setFilterNode] = useState('')
  const [autoScroll, setAutoScroll] = useState(true)
  const [isPaused, setIsPaused] = useState(false)

  // Manual transmit state
  const [manualId, setManualId] = useState('0x102')
  const [manualData, setManualData] = useState('11 22 33 44 55 66 77 88')
  const [manualNode, setManualNode] = useState('Manual_Console')
  const [transmitStatus, setTransmitStatus] = useState('')

  // Log Replay state
  const [replayFile, setReplayFile] = useState(null)
  const [replaySpeed, setReplaySpeed] = useState(1.0)
  const [replayMsg, setReplayMsg] = useState('')

  const traceEndRef = useRef(null)

  // Fetch status & nodes
  const fetchStatusAndNodes = async () => {
    try {
      const [sRes, nRes] = await Promise.all([
        fetch(`${apiBase}/api/busmaster/status`).then(r => r.json()),
        fetch(`${apiBase}/api/busmaster/nodes`).then(r => r.json()),
      ])
      setStatus(sRes)
      setRunning(sRes.running)
      if (nRes.nodes) setNodes(nRes.nodes)
    } catch (e) {
      console.error('Error fetching BUSMASTER status:', e)
    }
  }

  // Fetch trace buffer
  const fetchTrace = async () => {
    if (isPaused) return
    try {
      const res = await fetch(`${apiBase}/api/busmaster/trace?limit=200`).then(r => r.json())
      if (res.trace) {
        setTrace(res.trace)
      }
    } catch (e) {
      console.error('Error fetching BUSMASTER trace:', e)
    }
  }

  useEffect(() => {
    fetchStatusAndNodes()
    fetchTrace()
    const timer = setInterval(() => {
      fetchStatusAndNodes()
      fetchTrace()
    }, 1000)
    return () => clearInterval(timer)
  }, [isPaused])

  useEffect(() => {
    if (autoScroll && traceEndRef.current) {
      traceEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [trace, autoScroll])

  // Simulator actions
  const startSimulation = async () => {
    try {
      await fetch(`${apiBase}/api/busmaster/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ duration, bus_speed: busSpeed }),
      })
      fetchStatusAndNodes()
    } catch (e) {
      console.error(e)
    }
  }

  const stopSimulation = async () => {
    try {
      await fetch(`${apiBase}/api/busmaster/stop`, { method: 'POST' })
      fetchStatusAndNodes()
    } catch (e) {
      console.error(e)
    }
  }

  const toggleNode = async (nodeName, currentEnabled) => {
    try {
      await fetch(`${apiBase}/api/busmaster/nodes/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_name: nodeName, enabled: !currentEnabled }),
      })
      fetchStatusAndNodes()
    } catch (e) {
      console.error(e)
    }
  }

  const injectFault = async (nodeName, faultType) => {
    try {
      await fetch(`${apiBase}/api/busmaster/fault`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_name: nodeName, fault_type: faultType, duration: 5.0 }),
      })
      fetchStatusAndNodes()
    } catch (e) {
      console.error(e)
    }
  }

  const sendManualFrame = async (e) => {
    e.preventDefault()
    setTransmitStatus('Sending...')
    try {
      const res = await fetch(`${apiBase}/api/busmaster/transmit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          can_id: manualId,
          data: manualData,
          node_name: manualNode,
          channel: 1,
        }),
      }).then(r => r.json())

      if (res.status === 'transmitted') {
        setTransmitStatus('Frame Sent!')
        setTimeout(() => setTransmitStatus(''), 2500)
        fetchTrace()
        fetchStatusAndNodes()
      } else {
        setTransmitStatus('Error')
      }
    } catch (e) {
      setTransmitStatus('Failed')
    }
  }

  const handleExportLog = () => {
    window.open(`${apiBase}/api/busmaster/export-log`, '_blank')
  }

  const handleUploadReplay = async (e) => {
    e.preventDefault()
    if (!replayFile) return
    setReplayMsg('Uploading & Starting Playback...')
    const fd = new FormData()
    fd.append('file', replayFile)
    try {
      const res = await fetch(`${apiBase}/api/busmaster/upload-log?speed=${replaySpeed}`, {
        method: 'POST',
        body: fd,
      }).then(r => r.json())

      if (res.status === 'started') {
        setReplayMsg(`Playing ${res.file} (${res.total_messages} msgs)`)
      } else {
        setReplayMsg(`Error: ${res.error || 'Failed'}`)
      }
    } catch (e) {
      setReplayMsg('Playback failed to start')
    }
  }

  // Filter trace entries
  const filteredTrace = trace.filter(entry => {
    if (filterId && !entry.can_id_hex.toLowerCase().includes(filterId.toLowerCase())) return false
    if (filterNode && !entry.node_name.toLowerCase().includes(filterNode.toLowerCase())) return false
    return true
  })

  return (
    <div className="busmaster-container">
      {/* ─── Control Bar ─── */}
      <div className="bm-top-bar panel">
        <div className="bm-title-group">
          <div className="bm-brand">
            <span className="bm-badge">ETAS/BOSCH SPEC</span>
            <h2>BUSMASTER CAN Bus Network Simulator</h2>
          </div>
          <p className="panel-desc">
            Multi-node virtual ECU simulation, real-time trace inspection, fault injection, and native .log replay.
          </p>
        </div>

        <div className="bm-stats-row">
          <div className="bm-stat">
            <span className="bm-stat-label">Bus State</span>
            <span className={`bm-status-pill ${running ? 'active' : 'idle'}`}>
              {running ? 'TRANSMITTING' : 'IDLE / OFF'}
            </span>
          </div>

          <div className="bm-stat">
            <span className="bm-stat-label">Bus Load</span>
            <div className="bm-load-bar-wrap">
              <div
                className="bm-load-bar-fill"
                style={{ width: `${Math.min(100, (status?.bus_load_percent || 0))}%` }}
              />
              <span className="bm-load-text">{status?.bus_load_percent || 0}%</span>
            </div>
          </div>

          <div className="bm-stat">
            <span className="bm-stat-label">Total Messages</span>
            <span className="bm-stat-val">{(status?.total_messages || 0).toLocaleString()}</span>
          </div>

          <div className="bm-stat">
            <span className="bm-stat-label">Trace Frames</span>
            <span className="bm-stat-val">{(status?.trace_buffer_size || 0).toLocaleString()}</span>
          </div>

          <div className="bm-stat">
            <span className="bm-stat-label">Bitrate</span>
            <span className="bm-stat-val">{(status?.bus_speed || 500000) / 1000} kbps</span>
          </div>
        </div>

        <div className="bm-actions-row">
          <div className="bm-actions-left">
            <button
              className="btn btn-primary"
              onClick={startSimulation}
              disabled={running}
            >
              Start BUSMASTER Sim
            </button>
            <button
              className="btn btn-danger"
              onClick={stopSimulation}
              disabled={!running}
            >
              Stop Sim
            </button>
            <button className="btn btn-secondary" onClick={handleExportLog}>
              Export .log File
            </button>
          </div>

          <div className="bm-actions-right">
            <label>Bitrate:</label>
            <select
              value={busSpeed}
              onChange={e => setBusSpeed(Number(e.target.value))}
              disabled={running}
              className="select"
            >
              <option value="250000">250 kbps</option>
              <option value="500000">500 kbps (Standard)</option>
              <option value="1000000">1 Mbps (High Speed)</option>
            </select>
          </div>
        </div>
      </div>

      {/* ─── Grid: Simulated Nodes & Controls ─── */}
      <div className="bm-main-grid">
        {/* Left Column: Virtual ECU Nodes */}
        <div className="panel bm-nodes-panel">
          <div className="bm-panel-header">
            <h3>Virtual Nodes (ECU Network)</h3>
            <span className="bm-subtext">{nodes.length} Configured Nodes</span>
          </div>

          <div className="bm-nodes-list">
            {nodes.map(node => (
              <div
                key={node.name}
                className={`bm-node-card ${node.enabled ? 'node-enabled' : 'node-disabled'}`}
              >
                <div className="bm-node-top">
                  <div className="bm-node-info">
                    <span className="bm-node-name">{node.name}</span>
                    <span className="bm-node-ecu">{node.ecu_type.toUpperCase()}</span>
                    {node.fault_mode !== 'none' && (
                      <span className="bm-fault-badge">FAULT: {node.fault_mode.toUpperCase()}</span>
                    )}
                  </div>
                  <button
                    className={`btn btn-sm ${node.enabled ? 'btn-danger' : 'btn-primary'}`}
                    onClick={() => toggleNode(node.name, node.enabled)}
                  >
                    {node.enabled ? 'Disable' : 'Enable'}
                  </button>
                </div>

                <div className="bm-node-details">
                  <div className="bm-node-schedules">
                    {node.schedules.map((s, idx) => (
                      <span key={idx} className="bm-schedule-tag">
                        {s.can_id_hex} ({s.period_ms}ms)
                      </span>
                    ))}
                  </div>

                  <div className="bm-node-metrics">
                    <span>Tx: {node.tx_count.toLocaleString()}</span>
                    {node.error_count > 0 && <span className="bm-err-count">Err: {node.error_count}</span>}
                  </div>
                </div>

                {node.enabled && (
                  <div className="bm-node-fault-actions">
                    <span className="bm-fault-label">Inject Fault:</span>
                    <button
                      className="btn-tiny"
                      onClick={() => injectFault(node.name, 'burst')}
                    >
                      Burst
                    </button>
                    <button
                      className="btn-tiny"
                      onClick={() => injectFault(node.name, 'corrupt')}
                    >
                      Corrupt
                    </button>
                    <button
                      className="btn-tiny"
                      onClick={() => injectFault(node.name, 'bus_off')}
                    >
                      Bus-Off
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Manual Transmit Box */}
          <div className="bm-manual-transmit-box">
            <h4>Manual Frame Transmission</h4>
            <form onSubmit={sendManualFrame} className="bm-transmit-form">
              <div className="bm-form-row">
                <input
                  type="text"
                  placeholder="CAN ID (e.g. 0x102)"
                  value={manualId}
                  onChange={e => setManualId(e.target.value)}
                  className="input-text"
                  required
                />
                <input
                  type="text"
                  placeholder="Data Hex (e.g. 11 22 33 44)"
                  value={manualData}
                  onChange={e => setManualData(e.target.value)}
                  className="input-text"
                  required
                />
                <button type="submit" className="btn btn-warning">
                  Send Frame
                </button>
              </div>
              {transmitStatus && <span className="bm-transmit-feedback">{transmitStatus}</span>}
            </form>
          </div>

          {/* Upload and Replay BUSMASTER Log */}
          <div className="bm-replay-box">
            <h4>BUSMASTER Log Playback</h4>
            <form onSubmit={handleUploadReplay} className="bm-replay-form">
              <input
                type="file"
                accept=".log,.asc,.txt"
                onChange={e => setReplayFile(e.target.files[0])}
                className="file-input"
              />
              <div className="bm-replay-row">
                <label>Playback Speed:</label>
                <select
                  value={replaySpeed}
                  onChange={e => setReplaySpeed(parseFloat(e.target.value))}
                  className="select"
                >
                  <option value="1.0">1x (Real-Time)</option>
                  <option value="2.0">2x Accelerated</option>
                  <option value="5.0">5x Fast Forward</option>
                  <option value="10.0">10x Speed</option>
                  <option value="50.0">Max (Batch Analysis)</option>
                </select>
                <button type="submit" className="btn btn-primary" disabled={!replayFile}>
                  Replay in IDS
                </button>
              </div>
              {replayMsg && <div className="bm-replay-status">{replayMsg}</div>}
            </form>
          </div>
        </div>

        {/* Right Column: BUSMASTER Trace Window */}
        <div className="panel bm-trace-panel">
          <div className="bm-trace-header">
            <div className="bm-trace-title">
              <h3>BUSMASTER Live Trace Monitor</h3>
              <span className="bm-subtext">{filteredTrace.length} frames displayed</span>
            </div>

            <div className="bm-trace-controls">
              <input
                type="text"
                placeholder="Filter CAN ID (e.g. 102)"
                value={filterId}
                onChange={e => setFilterId(e.target.value)}
                className="input-tiny"
              />
              <input
                type="text"
                placeholder="Filter Node"
                value={filterNode}
                onChange={e => setFilterNode(e.target.value)}
                className="input-tiny"
              />
              <button
                className={`btn-tiny ${isPaused ? 'btn-active' : ''}`}
                onClick={() => setIsPaused(!isPaused)}
              >
                {isPaused ? 'Resume' : 'Pause'}
              </button>
              <button className="btn-tiny" onClick={() => setTrace([])}>
                Clear
              </button>
              <label className="bm-checkbox-label">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={e => setAutoScroll(e.target.checked)}
                />
                Auto-scroll
              </label>
            </div>
          </div>

          <div className="bm-trace-table-container">
            <table className="bm-trace-table">
              <thead>
                <tr>
                  <th>Time (s)</th>
                  <th>Dir</th>
                  <th>Ch</th>
                  <th>CAN ID</th>
                  <th>Node</th>
                  <th>Type</th>
                  <th>DLC</th>
                  <th>Data (Hex Bytes)</th>
                </tr>
              </thead>
              <tbody>
                {filteredTrace.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="bm-empty-cell">
                      No trace data recorded. Click "Start BUSMASTER Sim" or send a manual frame.
                    </td>
                  </tr>
                ) : (
                  filteredTrace.map((entry, i) => (
                    <tr key={i} className={`bm-trace-row dir-${entry.direction.toLowerCase()}`}>
                      <td className="bm-mono">{entry.time_str}</td>
                      <td>
                        <span className={`bm-dir-tag ${entry.direction.toLowerCase()}`}>
                          {entry.direction}
                        </span>
                      </td>
                      <td>{entry.channel}</td>
                      <td className="bm-mono bm-id-col">{entry.can_id_hex}</td>
                      <td className="bm-node-col">{entry.node_name}</td>
                      <td>{entry.frame_type}</td>
                      <td>{entry.dlc}</td>
                      <td className="bm-mono bm-data-col">{entry.data_hex}</td>
                    </tr>
                  ))
                )}
                <tr ref={traceEndRef} />
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
