export default function DevicesTable({ devices }) {
  if (!devices.length) {
    return (
      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Active Devices</h2>
        <p className="text-cyber-400 text-sm text-center py-4">No devices tracked yet.</p>
      </div>
    );
  }

  return (
    <div className="card">
      <h2 className="text-lg font-semibold mb-3">Active Devices</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-cyber-600/50 text-xs text-cyber-400 uppercase tracking-wider">
              <th className="px-4 py-2">IP Address</th>
              <th className="px-4 py-2">Alert Count</th>
              <th className="px-4 py-2">Connections</th>
              <th className="px-4 py-2">Risk</th>
              <th className="px-4 py-2">First Seen</th>
              <th className="px-4 py-2">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.ip} className="border-b border-cyber-700/30 hover:bg-cyber-700/20">
                <td className="px-4 py-2 font-mono text-cyber-accent">{d.ip}</td>
                <td className="px-4 py-2">{d.alert_count}</td>
                <td className="px-4 py-2">{d.connections ?? '-'}</td>
                <td className="px-4 py-2"><span className={`severity-badge severity-${d.risk_level || 'LOW'}`}>{d.risk_score ?? 0}/100 {d.risk_level || 'LOW'}</span></td>
                <td className="px-4 py-2 text-cyber-300">{d.first_seen ? new Date(d.first_seen).toLocaleString() : '-'}</td>
                <td className="px-4 py-2 text-cyber-300">{d.last_seen ? new Date(d.last_seen).toLocaleString() : '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
