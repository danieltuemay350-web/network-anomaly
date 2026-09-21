import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function AlertRow({ alert, onClick }) {
  return (
    <tr className="table-row" onClick={() => onClick(alert)}>
      <td className="px-4 py-3 text-sm text-cyber-300 whitespace-nowrap">
        {new Date(alert.timestamp).toLocaleTimeString()}
      </td>
      <td className="px-4 py-3">
        <span className={`severity-badge severity-${alert.severity}`}>{alert.severity}</span>
      </td>
      <td className="px-4 py-3 text-sm font-medium">{alert.alert_type}</td>
      <td className="px-4 py-3 text-sm font-mono text-cyber-accent">{alert.source_ip || '-'}</td>
      <td className="px-4 py-3 text-sm font-mono text-cyber-300">{alert.destination_ip || '-'}</td>
      <td className="px-4 py-3 text-sm text-cyber-300 max-w-xs truncate">{alert.description}</td>
      <td className="px-4 py-3">
        <span className={`severity-badge status-${alert.status}`}>{alert.status}</span>
      </td>
    </tr>
  );
}

export default function AlertTable({ alerts, onAlertClick, filterSeverity = null, onClearFilter }) {
  const [sortField, setSortField] = useState('timestamp');
  const [sortAsc, setSortAsc] = useState(false);

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const visible = filterSeverity ? alerts.filter((a) => a.severity === filterSeverity) : alerts;

  const sorted = [...visible].sort((a, b) => {
    if (sortField === 'severity') {
      const diff = (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99);
      return sortAsc ? diff : -diff;
    }
    if (sortField === 'timestamp') {
      const diff = new Date(a.timestamp) - new Date(b.timestamp);
      return sortAsc ? diff : -diff;
    }
    const val = (a[sortField] || '').toString().localeCompare((b[sortField] || '').toString());
    return sortAsc ? val : -val;
  });

  const SortIcon = ({ field }) => {
    if (sortField !== field) return null;
    return sortAsc ? <ChevronUp className="w-3 h-3 inline ml-1" /> : <ChevronDown className="w-3 h-3 inline ml-1" />;
  };

  const cols = [
    { key: 'timestamp', label: 'Time' },
    { key: 'severity', label: 'Severity' },
    { key: 'alert_type', label: 'Type' },
    { key: 'source_ip', label: 'Source' },
    { key: 'destination_ip', label: 'Destination' },
    { key: 'description', label: 'Description' },
    { key: 'status', label: 'Status' },
  ];

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold">Recent Alerts</h2>
        {filterSeverity && (
          <button
            type="button"
            onClick={onClearFilter}
            className="text-xs text-cyber-300 hover:text-cyber-accent flex items-center gap-1.5"
          >
            <span className={`severity-badge severity-${filterSeverity}`}>{filterSeverity}</span>
            Clear filter
            <span className="text-cyber-400">&times;</span>
          </button>
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-cyber-600/50 text-xs text-cyber-400 uppercase tracking-wider">
              {cols.map((c) => (
                <th
                  key={c.key}
                  className="px-4 py-2 cursor-pointer hover:text-cyber-accent select-none"
                  onClick={() => toggleSort(c.key)}
                >
                  {c.label}
                  <SortIcon field={c.key} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 && (
              <tr>
                <td colSpan={cols.length} className="px-4 py-8 text-center text-cyber-400">
                  {filterSeverity
                    ? `No ${filterSeverity} alerts in the current window.`
                    : 'No alerts yet. Waiting for traffic...'}
                </td>
              </tr>
            )}
            {sorted.map((a) => (
              <AlertRow key={a.id} alert={a} onClick={onAlertClick} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
