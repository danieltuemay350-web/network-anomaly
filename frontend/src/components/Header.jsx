import { Shield, Activity, Wifi, AlertTriangle } from 'lucide-react';

export default function Header({ captureStatus }) {
  return (
    <header className="bg-cyber-800 border-b border-cyber-600/30 px-6 py-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-cyber-accent" />
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">
              Network Anomaly Detector
            </h1>
            <p className="text-xs text-cyber-400">Real-time traffic monitoring &amp; threat detection</p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            {captureStatus.running ? (
              <Activity className="w-4 h-4 text-cyber-green" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-red-400" />
            )}
            <span className={captureStatus.running ? 'text-cyber-300' : 'text-red-300'}>
              {captureStatus.running ? 'Capture Active' : 'Capture Inactive'}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Wifi className="w-4 h-4 text-cyber-accent" />
            <span className="text-cyber-300">{captureStatus.interface || 'N/A'}</span>
            {captureStatus.auto_selected && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-700 text-cyber-300 uppercase tracking-wider">
                auto
              </span>
            )}
          </div>
          <div className="text-cyber-400">
            Packets: <span className="text-white font-mono">{captureStatus.packet_count?.toLocaleString() || 0}</span>
          </div>
        </div>
      </div>
      {!captureStatus.running && captureStatus.last_error && (
        <div className="mt-2 text-xs text-red-300 bg-cyber-900/60 border border-red-500/30 rounded px-3 py-1.5">
          Capture error: {captureStatus.last_error}
        </div>
      )}
      {captureStatus.configuration_warning && (
        <div className="mt-2 text-xs text-amber-200 bg-cyber-900/60 border border-amber-500/30 rounded px-3 py-1.5">
          Capture configuration: {captureStatus.configuration_warning}
        </div>
      )}
    </header>
  );
}
