import { useState, useEffect, useRef, useCallback } from 'react'
import './App.css'
import BusmasterPanel from './components/BusmasterPanel'

const API_BASE = 'http://localhost:8000'
const WS_URL = 'ws://localhost:8000/ws'

function formatHex(id) {
  if (typeof id === 'number') return `0x${id.toString(16).toUpperCase().padStart(3, '0')}`
  return id
}

function severityColor(sev) {
  const map = {
    NORMAL: '#4ade80', LOW: '#fbbf24', MEDIUM: '#f97316',
    HIGH: '#ef4444', CRITICAL: '#dc2626'
  }
  return map[sev] || '#94a3b8'
}

function severityBg(sev) {
  const map = {
    NORMAL: 'rgba(74,222,128,0.12)', LOW: 'rgba(251,191,36,0.12)',
    MEDIUM: 'rgba(249,115,22,0.12)', HIGH: 'rgba(239,68,68,0.12)',
    CRITICAL: 'rgba(220,38,38,0.18)'
  }
  return map[sev] || 'transparent'
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

function App() {
  const [status, setStatus] = useState(null)
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [authStatus, setAuthStatus] = useState(null)
  const [config, setConfig] = useState(null)
  const [connected, setConnected] = useState(false)
  const [simRunning, setSimRunning] = useState(false)
  const [analysisRunning, setAnalysisRunning] = useState(false)
  const [attackRunning, setAttackRunning] = useState(false)
  const [mode, setMode] = useState('simulation')
  const [attackType, setAttackType] = useState('FLOODING')
  const [tab, setTab] = useState('overview')
  const [selectedFile, setSelectedFile] = useState(null)
  const [playbackSpeed, setPlaybackSpeed] = useState(1.0)
  const wsRef = useRef(null)

  // ─── API Fetch ──────────────────────────────────────────────────────
  const fetchData = useCallback(async () => {
    try {
      const [sRes, eRes, aRes, mRes, authRes, cfgRes] = await Promise.all([
        fetch(`${API_BASE}/api/status`).then(r => r.json()),
        fetch(`${API_BASE}/api/security/events?limit=30`).then(r => r.json()),
        fetch(`${API_BASE}/api/security/alerts?limit=20`).then(r => r.json()),
        fetch(`${API_BASE}/api/metrics`).then(r => r.json()),
        fetch(`${API_BASE}/api/authentication/status`).then(r => r.json()),
        fetch(`${API_BASE}/api/config`).then(r => r.json()),
      ])
      setStatus(sRes)
      setEvents([...(eRes.events || [])].reverse())
      setAlerts([...(aRes.alerts || [])].reverse())
      setMetrics(mRes)
      setAuthStatus(authRes)
      setConfig(cfgRes)
      setSimRunning(sRes.simulation_running)
      setAnalysisRunning(sRes.analysis_running)
      setAttackRunning(sRes.attack_running)
      setMode(sRes.mode)
      setConnected(true)
    } catch (e) {
      setConnected(false)
    }
  }, [])

  // ─── WebSocket ──────────────────────────────────────────────────────
  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 2000)

    try {
      const ws = new WebSocket(WS_URL)
      ws.onopen = () => setConnected(true)
      ws.onclose = () => setConnected(false)
      ws.onmessage = (evt) => {
        const data = JSON.parse(evt.data)
        if (data.type === 'status') {
          setSimRunning(data.simulation_running)
          setAnalysisRunning(data.analysis_running)
          setAttackRunning(data.attack_running)
          if (data.recent_events) {
            setEvents(prev => {
              const reversed = [...data.recent_events].reverse();
              const newItems = reversed.filter(e => !prev.some(p => p.event_id === e.event_id));
              return [...newItems, ...prev].slice(0, 30);
            })
          }
          if (data.recent_alerts) {
            setAlerts(prev => {
              const reversed = [...data.recent_alerts].reverse();
              const newItems = reversed.filter(a => !prev.some(p => p.alert_id === a.alert_id));
              return [...newItems, ...prev].slice(0, 20);
            })
          }
        }
        if (data.type === 'alert') {
          setAlerts(prev => [data.alert, ...prev].slice(0, 20))
        }
      }
      wsRef.current = ws
    } catch (e) { /* WebSocket may fail if backend isn't running */ }

    return () => {
      clearInterval(interval)
      if (wsRef.current) wsRef.current.close()
    }
  }, [fetchData])

  // ─── Actions ────────────────────────────────────────────────────────
  const startSim = async () => {
    await fetch(`${API_BASE}/api/simulation/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ duration: 60 })
    })
    fetchData()
  }

  const stopSim = async () => {
    await fetch(`${API_BASE}/api/simulation/stop`, { method: 'POST' })
    fetchData()
  }

  const startAnalysis = async () => {
    if (!selectedFile) return
    const formData = new FormData()
    formData.append('file', selectedFile)
    
    await fetch(`${API_BASE}/api/analysis/upload?speed=${playbackSpeed}`, { 
      method: 'POST',
      body: formData
    })
    fetchData()
  }

  const stopAnalysis = async () => {
    await fetch(`${API_BASE}/api/analysis/stop`, { method: 'POST' })
    fetchData()
  }

  const startAttack = async () => {
    await fetch(`${API_BASE}/api/attacks/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: attackType, target_id: '0x102', duration: 10 })
    })
    fetchData()
  }

  const stopAttack = async () => {
    await fetch(`${API_BASE}/api/attacks/stop`, { method: 'POST' })
    fetchData()
  }

  // ─── Render ─────────────────────────────────────────────────────────
  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <div className="logo">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
              <circle cx="16" cy="16" r="14" stroke="url(#grad)" strokeWidth="2.5" fill="none" />
              <path d="M10 16h12M16 10v12M12 12l8 8M20 12l-8 8" stroke="url(#grad)" strokeWidth="1.5" strokeLinecap="round" />
              <defs><linearGradient id="grad" x1="0" y1="0" x2="32" y2="32"><stop stopColor="#60a5fa" /><stop offset="1" stopColor="#a78bfa" /></linearGradient></defs>
            </svg>
            <h1>CAN Security Framework</h1>
          </div>
          <span className="subtitle">Intrusion Detection & Message Authentication</span>
        </div>
        <div className="header-right">
          <span className={`status-badge ${connected ? 'connected' : 'disconnected'}`}>
            {connected ? 'Connected' : 'Disconnected'}
          </span>
          <span className={`mode-badge ${mode === 'analysis' ? 'analysis' : 'simulation'}`}>
            {mode.toUpperCase()}
          </span>
        </div>
      </header>

      <nav className="nav-tabs">
        {['overview', 'events', 'alerts', 'busmaster', mode === 'hybrid' ? 'operations' : 'controls'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t === 'busmaster'
              ? 'BUSMASTER Simulator'
              : t === 'operations'
              ? 'Operations'
              : t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </nav>

      <main className="content">
        {tab === 'overview' && <Overview status={status} metrics={metrics} authStatus={authStatus} config={config} alerts={alerts} />}
        {tab === 'events' && <EventsPanel events={events} />}
        {tab === 'alerts' && <AlertsPanel alerts={alerts} />}
        {tab === 'busmaster' && <BusmasterPanel apiBase={API_BASE} />}
        {(tab === 'controls' || tab === 'operations') && (
          <ControlsPanel
            mode={mode}
            simRunning={simRunning} attackRunning={attackRunning}
            analysisRunning={analysisRunning}
            attackType={attackType} setAttackType={setAttackType}
            startSim={startSim} stopSim={stopSim}
            startAttack={startAttack} stopAttack={stopAttack}
            startAnalysis={startAnalysis} stopAnalysis={stopAnalysis}
            selectedFile={selectedFile} setSelectedFile={setSelectedFile}
            playbackSpeed={playbackSpeed} setPlaybackSpeed={setPlaybackSpeed}
          />
        )}
      </main>

      <footer className="footer">
        <span>CAN Security Framework v0.1.0</span>
        <span>Research/Laboratory Use Only</span>
      </footer>
    </div>
  )
}

// ─── Overview ─────────────────────────────────────────────────────────────────

function Overview({ status, metrics, authStatus, config, alerts }) {
  const stats = [
    { label: 'Total Messages', value: status?.total_messages?.toLocaleString() || '0', icon: '&#xe167;' },
    { label: 'Alerts', value: status?.total_alerts?.toLocaleString() || '0', accent: '#f97316' },
    { label: 'Attacks Detected', value: status?.total_attacks_detected?.toLocaleString() || '0', accent: '#ef4444' },
    { label: 'Msg/s', value: metrics?.messages_per_second?.toFixed(1) || '0' },
    { label: 'CPU', value: `${metrics?.cpu_percent?.toFixed(1) || 0}%` },
    { label: 'Memory', value: `${metrics?.memory_mb?.toFixed(0) || 0} MB` },
  ]

  return (
    <div className="overview">
      <div className="stat-grid">
        {stats.map((s, i) => (
          <div key={i} className="stat-card" style={s.accent ? { borderColor: s.accent } : {}}>
            <div className="stat-value" style={s.accent ? { color: s.accent } : {}}>{s.value}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="panel-row">
        <div className="panel">
          <h3>System Configuration</h3>
          <div className="config-grid">
            <ConfigItem label="Mode" value={config?.mode || 'N/A'} />
            <ConfigItem label="CAN Interface" value={config?.can_interface || 'N/A'} />
            <ConfigItem label="CAN IDs" value={config?.can_ids || 0} />
            <ConfigItem label="Detection Rules" value={config?.detection_rules || 0} />
            <ConfigItem label="ML Model" value={config?.ml_model_type || 'N/A'} />
            <ConfigItem label="Auth" value={authStatus?.enabled ? 'Enabled' : 'Disabled'} ok={authStatus?.enabled} />
            <ConfigItem label="Freshness" value={config?.freshness_enabled ? 'Enabled' : 'Disabled'} ok={config?.freshness_enabled} />
            <ConfigItem label="Keys Loaded" value={authStatus?.keys_loaded || 0} />
          </div>
        </div>

        <div className="panel">
          <h3>Recent Alerts</h3>
          <div className="mini-alerts">
            {(alerts || []).slice(0, 5).map((a, i) => (
              <div key={i} className="mini-alert" style={{ borderLeft: `3px solid ${severityColor(a.severity)}` }}>
                <span className="mini-alert-sev" style={{ color: severityColor(a.severity) }}>{a.severity}</span>
                <span className="mini-alert-title">{a.title || a.description?.slice(0, 60)}</span>
              </div>
            ))}
            {(!alerts || alerts.length === 0) && <p className="empty-state">No alerts yet.</p>}
          </div>
        </div>
      </div>
    </div>
  )
}

function ConfigItem({ label, value, ok }) {
  return (
    <div className="config-item">
      <span className="config-label">{label}</span>
      <span className={`config-value ${ok === true ? 'ok' : ok === false ? 'warn' : ''}`}>
        {String(value)}
      </span>
    </div>
  )
}

// ─── Events Panel ─────────────────────────────────────────────────────────────

function EventsPanel({ events }) {
  return (
    <div className="panel full-width">
      <h3>Security Events</h3>
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th><th>CAN ID</th><th>Severity</th><th>Risk</th>
              <th>Attack Type</th><th>Status</th><th>Description</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={i} style={{ background: severityBg(e.severity) }}>
                <td className="mono">{new Date(e.timestamp * 1000).toLocaleTimeString()}</td>
                <td className="mono">{formatHex(e.can_id)}</td>
                <td><span className="sev-pill" style={{ background: severityColor(e.severity) }}>{e.severity}</span></td>
                <td className="mono">{e.risk_score?.toFixed(2)}</td>
                <td>{e.attack_type || 'N/A'}</td>
                <td>{e.status}</td>
                <td className="desc-cell">{e.description?.slice(0, 80)}</td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr><td colSpan="7" className="empty-state">No security events yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Alerts Panel ─────────────────────────────────────────────────────────────

function AlertsPanel({ alerts }) {
  return (
    <div className="panel full-width">
      <h3>Alerts</h3>
      <div className="alert-list">
        {alerts.map((a, i) => (
          <div key={i} className="alert-card" style={{ borderLeft: `4px solid ${severityColor(a.severity)}`, background: severityBg(a.severity) }}>
            <div className="alert-header">
              <span className="sev-pill" style={{ background: severityColor(a.severity) }}>{a.severity}</span>
              <span className="alert-type">{a.attack_type}</span>
              <span className="alert-time">{new Date(a.timestamp * 1000).toLocaleTimeString()}</span>
            </div>
            <div className="alert-title">{a.title}</div>
            <div className="alert-desc">{a.description}</div>
            <div className="alert-meta">
              <span>Risk: {a.risk_score?.toFixed(2)}</span>
              <span>CAN ID: {formatHex(a.can_id)}</span>
            </div>
          </div>
        ))}
        {alerts.length === 0 && <p className="empty-state">No alerts.</p>}
      </div>
    </div>
  )
}

// ─── Controls Panel ───────────────────────────────────────────────────────────

function ControlsPanel({ mode, simRunning, analysisRunning, attackRunning, attackType, setAttackType, startSim, stopSim, startAttack, stopAttack, startAnalysis, stopAnalysis, selectedFile, setSelectedFile, playbackSpeed, setPlaybackSpeed }) {
  const attacks = ['FLOODING', 'INJECTION', 'REPLAY', 'SPOOFING', 'ABNORMAL_FREQUENCY']

  if (mode === 'hybrid') {
    return (
      <div className="controls" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        <div className="panel">
          <h3>Simulation Network</h3>
          <p className="panel-desc">Generate mock CAN traffic across 6 virtual ECUs (Engine, Brake, Steering, Transmission, Infotainment, Gateway).</p>
          <div className="btn-group" style={{ marginTop: '20px' }}>
            <button className="btn btn-primary" onClick={startSim} disabled={simRunning || analysisRunning}>Start Simulation</button>
            <button className="btn btn-danger" onClick={stopSim} disabled={!simRunning}>Stop Simulation</button>
          </div>
          <div className={`status-indicator ${simRunning ? 'running' : 'stopped'}`}>
            {simRunning ? 'Generating Normal Traffic...' : 'Simulation Stopped'}
          </div>
        </div>

        <div className="panel">
          <h3>Log Analysis & Playback</h3>
          <p className="panel-desc">Upload a CAN log file (.asc, .csv) to analyze historical traffic.</p>
          
          <div className="upload-zone" style={{ marginBottom: '16px', marginTop: '10px' }}>
             <input type="file" accept=".asc,.csv,.log" onChange={e => setSelectedFile(e.target.files[0])} disabled={analysisRunning || simRunning} className="file-input" style={{marginBottom: '10px'}}/>
             <div style={{display: 'flex', gap: '10px', alignItems: 'center'}}>
                <label>Speed:</label>
                <select value={playbackSpeed} onChange={e => setPlaybackSpeed(parseFloat(e.target.value))} disabled={analysisRunning || simRunning} className="select">
                   <option value="1.0">1x (Real-time)</option>
                   <option value="2.0">2x Fast Forward</option>
                   <option value="10.0">10x Fast Forward</option>
                   <option value="0.0">Max Speed (No Sleep)</option>
                </select>
             </div>
          </div>

          <div className="btn-group">
            <button className="btn btn-primary" onClick={startAnalysis} disabled={analysisRunning || simRunning || !selectedFile}>Start Analysis</button>
            <button className="btn btn-danger" onClick={stopAnalysis} disabled={!analysisRunning}>Stop Analysis</button>
          </div>
          <div className={`status-indicator ${analysisRunning ? 'running' : 'stopped'}`}>
            {analysisRunning ? 'Processing Log File...' : 'Analysis Stopped'}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="controls" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      <div className="panel">
        <h3>Simulation Network</h3>
        <p className="panel-desc">Start the vehicle CAN bus simulation to generate realistic traffic.</p>
        <div className="btn-group">
          <button className="btn btn-primary" onClick={startSim} disabled={simRunning}>Start Simulation</button>
          <button className="btn btn-danger" onClick={stopSim} disabled={!simRunning}>Stop Simulation</button>
        </div>
        <div className={`status-indicator ${simRunning ? 'running' : 'stopped'}`}>
          {simRunning ? 'Simulation Running' : 'Simulation Stopped'}
        </div>
      </div>

      <div className="panel">
        <h3>Attack Simulation</h3>
        <div className="warning-banner">
          WARNING: SIMULATION MODE ONLY. Never connect to real vehicles.
        </div>
        <div className="attack-controls">
          <label>Attack Type:</label>
          <select value={attackType} onChange={e => setAttackType(e.target.value)} className="select">
            {attacks.map(a => <option key={a} value={a}>{a.replace('_', ' ')}</option>)}
          </select>
        </div>
        <div className="btn-group">
          <button className="btn btn-warning" onClick={startAttack} disabled={!simRunning || attackRunning}>
            Launch Attack
          </button>
          <button className="btn btn-danger" onClick={stopAttack} disabled={!attackRunning}>
            Stop Attack
          </button>
        </div>
        <div className={`status-indicator ${attackRunning ? 'attack' : 'stopped'}`}>
          {attackRunning ? `Attack Active: ${attackType}` : 'No Active Attack'}
        </div>
      </div>
    </div>
  )
}

export default App
