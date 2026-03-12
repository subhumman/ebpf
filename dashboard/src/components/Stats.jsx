function Stats({ stats }) {
  const statItems = [
    { label: 'Total Events', value: stats.total, color: '#00d9ff' },
    { label: 'File Events', value: stats.fileEvents, color: '#6bcb77' },
    { label: 'Network Events', value: stats.networkEvents, color: '#4d96ff' },
    { label: 'Active Alerts', value: stats.alerts, color: '#ff6b6b' },
  ]

  return (
    <div className="stats-grid">
      {statItems.map((stat, index) => (
        <div className="stat-card" key={index}>
          <div 
            className="stat-value"
            style={{ color: stat.color }}
          >
            {stat.value}
          </div>
          <div className="stat-label">{stat.label}</div>
        </div>
      ))}
    </div>
  )
}

export default Stats