import { X } from 'lucide-react';

export default function IncidentDetail({ incident, onClose, onAction }) {
  if (!incident) return null;
  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
    <div className="bg-cyber-800 border border-cyber-600/40 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto mx-4 shadow-2xl" onClick={(e) => e.stopPropagation()}>
      <div className="flex items-center justify-between px-5 py-4 border-b border-cyber-700/50"><h2 className="text-lg font-bold">Incident Investigation</h2><button onClick={onClose}><X className="w-5 h-5" /></button></div>
      <div className="p-5 space-y-5">
        <div className="flex items-center gap-3"><span className={`severity-badge severity-${incident.severity}`}>{incident.severity}</span><span className="text-2xl font-bold text-cyber-accent">Risk {incident.risk_score}/100</span></div>
        <p className="text-cyber-200">{incident.description}</p>
        <section><h3 className="text-sm font-semibold mb-2">Risk contributors</h3>{(incident.risk_contributors || []).map((item) => <div key={item.id} className="py-1 text-sm"><span className="font-mono text-cyber-accent">{item.category}</span> <span className="font-bold">+{item.score}</span> — {item.explanation}</div>)}</section>
        <div className="grid grid-cols-2 gap-3 text-sm"><Info label="Source" value={incident.source_ip} /><Info label="Destination" value={incident.destination_ip} /><Info label="First seen" value={incident.first_seen && new Date(incident.first_seen).toLocaleString()} /><Info label="Last seen" value={incident.last_seen && new Date(incident.last_seen).toLocaleString()} /></div>
        <section><h3 className="text-sm font-semibold mb-2">Contributing detections</h3>{(incident.alerts || []).map((alert) => <div key={alert.id} className="py-2 border-b border-cyber-700/40 text-sm"><span className="font-mono text-cyber-accent">{alert.alert_type}</span> <span className="text-cyber-400">×{alert.occurrences || 1}</span> — {alert.description}</div>)}</section>
        <section><h3 className="text-sm font-semibold mb-2">Timeline</h3>{(incident.timeline || []).map((event) => <div key={event.id} className="py-1.5 text-sm"><span className="font-mono text-cyber-400">{new Date(event.timestamp).toLocaleTimeString()}</span> <span className="ml-2">{event.description}</span></div>)}</section>
        <div className="flex gap-2"><button onClick={() => onAction('acknowledge')} className="px-3 py-1.5 rounded bg-cyber-700 text-cyber-200">Acknowledge</button><button onClick={() => onAction('resolve')} className="px-3 py-1.5 rounded bg-cyber-accent/20 text-cyber-accent">Resolve</button></div>
      </div>
    </div>
  </div>;
}
function Info({ label, value }) { return <div><span className="text-cyber-400 text-xs">{label}</span><p className="text-white">{value || '-'}</p></div>; }
