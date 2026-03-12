import { format } from 'date-fns'

function Alerts({ alerts }) {
  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'critical'
      case 'high':
        return 'high'
      case 'medium':
        return 'medium'
      default:
        return 'medium'
    }
  }

  if (alerts.length === 0) {
    return (
      <div className="panel">
        <div className="panel-header">
          <h2 className="panel-title">🚨 Alerts</h2>
        </div>
        <div className="no-data">
          <p>No active alerts</p>
          <p style={{ fontSize: '0.85rem', marginTop: '10px', color: '#6bcb77' }}>
            ✓ System is secure
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <h2 className="panel-title">🚨 Alerts</h2>
        <span 
          className="badge"
          style={{
            background: alerts.length > 0 ? 'rgba(255, 107, 107, 0.2)' : 'rgba(107, 203, 119, 0.2)',
            color: alerts.length > 0 ? '#ff6b6b' : '#6bcb77',
            border: `1px solid ${alerts.length > 0 ? '#ff6b6b' : '#6bcb77'}`
          }}
        >
          {alerts.length} Active
        </span>
      </div>
      
      <div>
        {alerts.map((alert, index) => (
          <div 
            key={index}
            className={`alert-item ${getSeverityClass(alert.severity)}`}
          >
            <div className="alert-header">
              <span className={`alert-severity ${getSeverityClass(alert.severity)}`}>
                {alert.severity}
              </span>
              <span style={{ color: '#8892b0', fontSize: '0.85rem' }}>
                {alert.rule_id}
              </span>
            </div>
            <div className="alert-message">{alert.message}</div>
            {alert.timestamp && (
              <div className="alert-time">
                {format(new Date(alert.timestamp), 'HH:mm:ss')}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export default Alerts