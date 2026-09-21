import { ShieldAlert, AlertTriangle, AlertCircle, Info } from 'lucide-react';

const CARDS = [
  ['open_incidents', 'Open Incidents', ShieldAlert, 'text-cyber-accent'],
  ['critical', 'Critical', AlertTriangle, 'text-red-400'],
  ['high', 'High', AlertCircle, 'text-orange-400'],
  ['medium', 'Medium', AlertTriangle, 'text-yellow-400'],
  ['low', 'Low', Info, 'text-green-400'],
];

const SEVERITY = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

export default function IncidentOverview({ overview = {}, activeSeverity, activeStatus, onSelect }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
      {CARDS.map(([key, label, Icon, color]) => (
        <button
          key={key}
          type="button"
          onClick={() => key === 'open_incidents' ? onSelect(null, 'OPEN') : onSelect(SEVERITY[key], null)}
          className={`stat-card text-left cursor-pointer hover:border-cyber-accent/40 ${(activeSeverity === SEVERITY[key] || (key === 'open_incidents' && activeStatus === 'OPEN')) ? 'border-cyber-accent ring-1 ring-cyber-accent/40' : ''}`}
          title={key === 'open_incidents' ? 'Show unresolved incidents' : activeSeverity === SEVERITY[key] ? 'Clear incident filter' : `Show ${label.toLowerCase()} incidents`}
        >
          <div className="flex items-center justify-between">
            <Icon className={`w-5 h-5 ${color}`} />
            <span className={`text-3xl font-bold ${color}`}>{overview[key] ?? 0}</span>
          </div>
          <span className="stat-label">{label}</span>
        </button>
      ))}
    </div>
  );
}
