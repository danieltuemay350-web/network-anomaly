export default function IncidentTable({ incidents, onSelect, severityFilter, statusFilter, onClearFilter }) {
  const visible = incidents.filter((incident) =>
    (!severityFilter || incident.severity === severityFilter) &&
    (!statusFilter || (statusFilter === 'OPEN' ? incident.status !== 'RESOLVED' : incident.status === statusFilter)),
  );
  return (
    <div className="card overflow-hidden">
      <div className="flex items-center justify-between gap-3 mb-3">
        <h2 className="text-lg font-semibold">Active Incidents</h2>
        <div className="flex items-center gap-2">
          <select value={statusFilter || ''} onChange={(event) => onClearFilter(severityFilter, event.target.value || null)} className="bg-cyber-900 border border-cyber-600 rounded px-2 py-1 text-xs text-cyber-200">
            <option value="">All statuses</option><option value="OPEN">Open</option><option value="NEW">New</option><option value="ACKNOWLEDGED">Acknowledged</option><option value="RESOLVED">Resolved</option>
          </select>
          {(severityFilter || statusFilter) && <button onClick={() => onClearFilter(null, null)} className="text-xs text-cyber-accent hover:text-white">Clear filters ×</button>}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead><tr className="border-b border-cyber-600/50 text-xs text-cyber-400 uppercase tracking-wider">
            <th className="px-4 py-2">Severity</th><th className="px-4 py-2">Incident</th><th className="px-4 py-2">Source</th><th className="px-4 py-2">Target</th><th className="px-4 py-2">Risk</th><th className="px-4 py-2">Events</th><th className="px-4 py-2">Status</th>
          </tr></thead>
          <tbody>{visible.length ? visible.map((incident) => (
            <tr key={incident.id} onClick={() => onSelect(incident.id)} className="table-row">
              <td className="px-4 py-3"><span className={`severity-badge severity-${incident.severity}`}>{incident.severity}</span></td>
              <td className="px-4 py-3 font-medium">{incident.title}</td>
              <td className="px-4 py-3 font-mono text-cyber-accent">{incident.source_ip || '-'}</td>
              <td className="px-4 py-3 font-mono">{incident.destination_ip || '-'}</td>
              <td className="px-4 py-3 font-bold">{incident.risk_score}/100</td>
              <td className="px-4 py-3">{incident.alert_count}</td>
              <td className="px-4 py-3"><span className={`severity-badge status-${incident.status}`}>{incident.status}</span></td>
            </tr>
          )) : <tr><td colSpan="7" className="px-4 py-8 text-center text-cyber-400">No incidents match the current filter.</td></tr>}</tbody>
        </table>
      </div>
    </div>
  );
}
