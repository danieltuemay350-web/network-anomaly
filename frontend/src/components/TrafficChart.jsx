import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

export default function TrafficChart({ data }) {
  const chartData = data.map((d) => ({
    time: new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    'Packets/s': d.packets_per_second,
    'Bytes/s': d.bytes_per_second / 1024,
  }));

  return (
    <div className="card">
      <h2 className="text-lg font-semibold mb-3">Traffic Over Time</h2>
      <div className="h-64">
        {chartData.length === 0 ? (
          <div className="h-full flex items-center justify-center text-cyber-400">
            Collecting traffic data...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="time"
                stroke="#64748b"
                fontSize={11}
                tick={{ fill: '#94a3b8' }}
              />
              <YAxis stroke="#64748b" fontSize={11} tick={{ fill: '#94a3b8' }} />
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #475569', borderRadius: 8 }}
                labelStyle={{ color: '#94a3b8' }}
              />
              <Legend />
              <Line type="monotone" dataKey="Packets/s" stroke="#22d3ee" dot={false} strokeWidth={2} />
              <Line type="monotone" dataKey="Bytes/s" stroke="#34d399" dot={false} strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
