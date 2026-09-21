import { ShieldAlert, AlertTriangle, AlertCircle, Info, MonitorSmartphone } from 'lucide-react';

const CARDS = [
  { key: 'total_alerts', label: 'Total Alerts', Icon: ShieldAlert, color: 'text-cyber-accent' },
  { key: 'critical_severity', label: 'Critical', Icon: AlertTriangle, color: 'text-red-400' },
  { key: 'high_severity', label: 'High', Icon: AlertCircle, color: 'text-orange-400' },
  { key: 'medium_severity', label: 'Medium', Icon: AlertTriangle, color: 'text-yellow-400' },
  { key: 'low_severity', label: 'Low', Icon: Info, color: 'text-green-400' },
  { key: 'unique_source_ips', label: 'Active IPs', Icon: MonitorSmartphone, color: 'text-purple-400' },
];

const SEVERITY_KEY = {
  critical_severity: 'CRITICAL',
  high_severity: 'HIGH',
  medium_severity: 'MEDIUM',
  low_severity: 'LOW',
};

export default function StatsOverview({ stats, activeFilter = null, onCardClick }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {CARDS.map(({ key, label, Icon, color }) => {
        const isSeverity = key in SEVERITY_KEY;
        const filterValue = isSeverity ? SEVERITY_KEY[key] : null;
        const isFilterable = isSeverity || key === 'total_alerts';
        const isActive = isFilterable && activeFilter === filterValue;
        return (
          <button
            key={key}
            type="button"
            disabled={!isFilterable}
            onClick={() => onCardClick(filterValue)}
            className={`stat-card group text-left transition-colors ${
              isFilterable
                ? 'cursor-pointer hover:border-cyber-accent/40'
                : 'cursor-default'
            } ${isActive ? 'border-cyber-accent ring-1 ring-cyber-accent/40' : ''}`}
            title={
              isFilterable
                ? isActive
                  ? 'Clear filter'
                  : `Filter alerts to ${label.toLowerCase()} severity`
                : ''
            }
          >
            <div className="flex items-center justify-between">
              <Icon className={`w-5 h-5 ${color}`} />
              <span className={`text-3xl font-bold ${color}`}>
                {stats[key] ?? 0}
              </span>
            </div>
            <span className="stat-label">{label}</span>
          </button>
        );
      })}
    </div>
  );
}
