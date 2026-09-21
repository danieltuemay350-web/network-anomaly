import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from 'recharts';

const TYPE_LABELS = {
  PORT_SCAN: 'Port Scans',
  CONNECTION_ANOMALY: 'Connection Anomalies',
  TRAFFIC_ANOMALY: 'Traffic Anomalies',
  DNS_ANOMALY: 'DNS Anomalies',
  SUSPICIOUS_OUTBOUND: 'Suspicious Outbound',
};

const COLORS = {
  PORT_SCAN: '#f87171',
  CONNECTION_ANOMALY: '#fbbf24',
  TRAFFIC_ANOMALY: '#22d3ee',
  DNS_ANOMALY: '#a78bfa',
  SUSPICIOUS_OUTBOUND: '#fb923c',
};

export default function DetectionSummary({ stats }) {
  const typeCounts = stats.alerts_by_type || {};

  const chartData = Object.entries(TYPE_LABELS).map(([key, label]) => ({
    type: label,
    count: typeCounts[key] || 0,
    fullMark: Math.max(...Object.values(typeCounts), 10),
  }));

  const totalDetections = Object.values(typeCounts).reduce((a, b) => a + b, 0);

  return (
    <div className="card">
      <h2 className="text-lg font-semibold mb-3">Detection Summary</h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="space-y-2">
          {Object.entries(TYPE_LABELS).map(([key, label]) => (
            <div key={key} className="flex items-center justify-between py-1.5 border-b border-cyber-700/30">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ background: COLORS[key] }} />
                <span className="text-sm text-cyber-300">{label}</span>
              </div>
              <span className="text-lg font-bold" style={{ color: COLORS[key] }}>
                {typeCounts[key] || 0}
              </span>
            </div>
          ))}
          <div className="flex items-center justify-between pt-2 border-t border-cyber-600/50">
            <span className="text-sm font-medium text-white">Total Detections</span>
            <span className="text-xl font-bold text-cyber-accent">{totalDetections}</span>
          </div>
        </div>
        <div className="h-52">
          {totalDetections > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={chartData}>
                <PolarGrid stroke="#334155" />
                <PolarAngleAxis dataKey="type" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <PolarRadiusAxis tick={{ fill: '#64748b', fontSize: 10 }} />
                <Radar
                  name="Count"
                  dataKey="count"
                  stroke="#22d3ee"
                  fill="#22d3ee"
                  fillOpacity={0.2}
                />
                <Tooltip
                  contentStyle={{ background: '#1e293b', border: '1px solid #475569', borderRadius: 8 }}
                />
              </RadarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-cyber-400">
              No detections yet
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
