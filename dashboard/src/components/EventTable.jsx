import { format } from 'date-fns'

function EventTable({ events }) {
  const getEventTypeBadge = (type) => {
    switch (type) {
      case 1:
        return <span className="badge badge-file">File Open</span>
      case 2:
        return <span className="badge badge-network">Network</span>
      default:
        return <span className="badge">Unknown</span>
    }
  }

  const getEventDetails = (event) => {
    if (event.event_type === 1) {
      return event.filename || 'N/A'
    } else if (event.event_type === 2) {
      return `${event.dest_ip}:${event.dest_port}`
    }
    return 'N/A'
  }

  if (events.length === 0) {
    return (
      <div className="no-data">
        <p>No events recorded yet</p>
        <p style={{ fontSize: '0.9rem', marginTop: '10px' }}>
          Events will appear here as they are captured by the eBPF agent
        </p>
      </div>
    )
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="events-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>PID</th>
            <th>UID</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => (
            <tr key={index}>
              <td>
                {format(new Date(event.created_at), 'HH:mm:ss')}
              </td>
              <td>{getEventTypeBadge(event.event_type)}</td>
              <td>{event.pid}</td>
              <td>{event.uid}</td>
              <td style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>
                {getEventDetails(event)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default EventTable