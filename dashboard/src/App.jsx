import { useState, useEffect } from 'react'
import Stats from './components/Stats'
import EventTable from './components/EventTable'
import Alerts from './components/Alerts'
import { fetchEvents, fetchAlerts } from './api/events'

function App() {
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastUpdate, setLastUpdate] = useState(null)

  const loadData = async () => {
    try {
      setLoading(true)
      const [eventsData, alertsData] = await Promise.all([
        fetchEvents(100),
        fetchAlerts()
      ])
      setEvents(eventsData)
      setAlerts(alertsData)
      setLastUpdate(new Date())
      setError(null)
    } catch (err) {
      setError('Failed to load data from backend. Make sure the backend is running on http://localhost:8000')
      console.error('Error loading data:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    
    // Auto-refresh every 5 seconds
    const interval = setInterval(loadData, 5000)
    return () => clearInterval(interval)
  }, [])

  const stats = {
    total: events.length,
    fileEvents: events.filter(e => e.event_type === 1).length,
    networkEvents: events.filter(e => e.event_type === 2).length,
    alerts: alerts.length
  }

  return (
    <div className="container">
      <header className="header">
        <h1>🛡️ eBPF Security Monitor</h1>
        <p>Real-time kernel-level security monitoring</p>
        {lastUpdate && (
          <p style={{ fontSize: '0.9rem', color: '#8892b0', marginTop: '10px' }}>
            Last updated: {lastUpdate.toLocaleTimeString()}
          </p>
        )}
      </header>

      <Stats stats={stats} />

      {error && <div className="error">{error}</div>}

      {loading ? (
        <div className="loading">Loading security data...</div>
      ) : (
        <div className="content-grid">
          <div className="panel">
            <div className="panel-header">
              <h2 className="panel-title">Recent Events</h2>
              <button className="refresh-btn" onClick={loadData}>
                Refresh
              </button>
            </div>
            <EventTable events={events} />
          </div>

          <div>
            <Alerts alerts={alerts} />
          </div>
        </div>
      )}

      <footer className="footer">
        <p>eBPF Security Agent v1.0.0 | Monitoring kernel syscalls in real-time</p>
      </footer>
    </div>
  )
}

export default App