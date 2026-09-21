import { X } from 'lucide-react';

export default function AlertDetail({ alert, onClose, onStatusChange }) {
  if (!alert) return null;

  const meta = alert.metadata ? (typeof alert.metadata === 'string' ? JSON.parse(alert.metadata) : alert.metadata) : {};

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-cyber-800 border border-cyber-600/40 rounded-2xl w-full max-w-lg mx-4 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-cyber-700/50">
          <h2 className="text-lg font-bold">Alert Details</h2>
          <button onClick={onClose} className="text-cyber-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          <div className="flex items-center gap-3">
            <span className={`severity-badge severity-${alert.severity}`}>{alert.severity}</span>
            <span className="font-mono text-sm text-cyber-accent">{alert.alert_type}</span>
          </div>

          <p className="text-sm text-cyber-200">{alert.description}</p>

          <div className="grid grid-cols-2 gap-3 text-sm">
            <InfoRow label="Source IP" value={alert.source_ip} mono />
            <InfoRow label="Destination IP" value={alert.destination_ip} mono />
            <InfoRow label="Source Port" value={alert.source_port} />
            <InfoRow label="Destination Port" value={alert.destination_port} />
            <InfoRow label="Protocol" value={alert.protocol} />
            <InfoRow label="Status" value={alert.status} />
            <InfoRow label="Time" value={alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '-'} span={2} />
          </div>

          {Object.keys(meta).length > 0 && (
            <div>
              <h3 className="text-xs uppercase text-cyber-400 tracking-wider mb-2">Metadata</h3>
              <pre className="bg-cyber-900 rounded-lg p-3 text-xs text-cyber-300 overflow-x-auto">
                {JSON.stringify(meta, null, 2)}
              </pre>
            </div>
          )}

          <div className="flex gap-2 pt-2">
            {['NEW', 'ACKNOWLEDGED', 'RESOLVED'].map((s) => (
              <button
                key={s}
                onClick={() => onStatusChange(alert.id, s)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  alert.status === s
                    ? 'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/40'
                    : 'bg-cyber-700 text-cyber-300 hover:bg-cyber-600 border border-transparent'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value, mono = false, span = 1 }) {
  return (
    <div className={span === 2 ? 'col-span-2' : ''}>
      <span className="text-cyber-400 text-xs">{label}</span>
      <p className={`${mono ? 'font-mono text-cyber-accent' : 'text-white'} text-sm`}>{value || '-'}</p>
    </div>
  );
}
