import { useState, useEffect, useCallback } from 'react';
import { api } from './services/api';
import Header from './components/Header';
import StatsOverview from './components/StatsOverview';
import AlertTable from './components/AlertTable';
import TrafficChart from './components/TrafficChart';
import DetectionSummary from './components/DetectionSummary';
import AlertDetail from './components/AlertDetail';
import DevicesTable from './components/DevicesTable';
import IncidentOverview from './components/IncidentOverview';
import IncidentTable from './components/IncidentTable';
import IncidentDetail from './components/IncidentDetail';
import SecurityControls from './components/SecurityControls';
import ThreatIntelligence from './components/ThreatIntelligence';

const POLL_INTERVAL = 3000;

export default function App() {
  const [stats, setStats] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [devices, setDevices] = useState([]);
  const [traffic, setTraffic] = useState([]);
  const [captureStatus, setCaptureStatus] = useState({ running: false, packet_count: 0 });
  const [incidents, setIncidents] = useState([]);
  const [incidentOverview, setIncidentOverview] = useState({});
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [incidentSeverityFilter, setIncidentSeverityFilter] = useState(null);
  const [incidentStatusFilter, setIncidentStatusFilter] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [severityFilter, setSeverityFilter] = useState(null);
  const [rules, setRules] = useState([]);
  const [trustedDevices, setTrustedDevices] = useState([]);
  const [suppressions, setSuppressions] = useState([]);
  const [activity, setActivity] = useState([]);
  const [network, setNetwork] = useState({ interfaces: [], mode: 'auto', selected_interface: null });
  const [view, setView] = useState('dashboard');
  const [tiStats, setTiStats] = useState({});
  const [tiIndicators, setTiIndicators] = useState([]);
  const [tiMatches, setTiMatches] = useState([]);
  const [aiInvestigations, setAiInvestigations] = useState([]);

  const refresh = useCallback(async () => {
    try {
      const [s, a, d, t, c, i, r, td, su, ac, ni, tis, tii, tim, aii] = await Promise.all([
        api.stats(),
        api.alerts({ limit: 200 }),
        api.devices(),
        api.traffic(60),
        api.captureStatus(),
        api.incidents({ limit: 100 }),
        api.rules(), api.trustedDevices(), api.suppressions(), api.activity(), api.networkInterfaces(),
        api.tiStats(), api.tiIndicators(), api.tiMatches(), api.aiInvestigations(),
      ]);
      setStats(s);
      setAlerts(a.alerts || []);
      setDevices(d.devices || []);
      setTraffic(t.traffic || []);
      setCaptureStatus(c);
      setIncidents(i.incidents || []);
      setIncidentOverview(i.overview || {});
      setRules(r.rules || []); setTrustedDevices(td.devices || []); setSuppressions(su.suppressions || []); setActivity(ac.events || []);
      setNetwork(ni);
      setTiStats(tis); setTiIndicators(tii.indicators || []); setTiMatches(tim.matches || []);
      setAiInvestigations(aii.investigations || []);
    } catch (err) {
      console.error('Poll error:', err);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [refresh]);

  const handleAlertClick = (alert) => setSelectedAlert(alert);

  const handleStatusChange = async (id, status) => {
    try {
      await api.updateAlert(id, status);
      setSelectedAlert(null);
      refresh();
    } catch (err) {
      console.error('Update failed:', err);
    }
  };

  const selectIncident = async (id) => {
    try { setSelectedIncident(await api.incident(id)); } catch (err) { console.error('Incident load failed:', err); }
  };
  const updateIncident = async (action) => {
    try {
      const updated = action === 'acknowledge' ? await api.acknowledgeIncident(selectedIncident.id) : await api.resolveIncident(selectedIncident.id);
      setSelectedIncident(updated); refresh();
    } catch (err) { console.error('Incident update failed:', err); }
  };
  const setIncidentFilters = (severity, status = incidentStatusFilter) => {
    setIncidentSeverityFilter(severity === incidentSeverityFilter ? null : severity);
    setIncidentStatusFilter(status === incidentStatusFilter && !severity ? null : status);
  };
  const saveRule = async (type, body) => { await api.updateRule(type, body); refresh(); };
  const addTrusted = async (body) => { try { await api.addTrustedDevice(body); refresh(); } catch (err) { alert(err.message); } };
  const deleteTrusted = async (id) => { await api.deleteTrustedDevice(id); refresh(); };
  const addSuppression = async (body) => { try { await api.addSuppression(body); refresh(); } catch (err) { alert(err.message); } };
  const saveNetwork = async (body) => { try { await api.updateNetworkConfig(body); await refresh(); } catch (err) { alert(err.message); } };
  const addTi = async (body) => { await api.createTiIndicator(body); refresh(); };
  const disableTi = async (id) => { await api.disableTiIndicator(id); refresh(); };
  const importTi = async (body) => { const result = await api.importTi(body); refresh(); return result; };
  const investigateAi = async (body) => { const result = await api.investigateAi(body); refresh(); return result; };

  return (
    <div className="min-h-screen flex flex-col">
      <Header captureStatus={captureStatus} />
      <nav className="bg-cyber-800 border-b border-cyber-700/50 px-6">
        <div className="max-w-[1600px] mx-auto flex gap-2">
          <NavButton active={view === 'dashboard'} onClick={() => setView('dashboard')}>Dashboard</NavButton>
          <NavButton active={view === 'controls'} onClick={() => setView('controls')}>Rules &amp; Controls</NavButton>
          <NavButton active={view === 'ti'} onClick={() => setView('ti')}>Threat Intelligence</NavButton>
        </div>
      </nav>
      <main className="flex-1 p-6 space-y-6 max-w-[1600px] mx-auto w-full">
        {view === 'dashboard' ? <>
        <StatsOverview stats={stats} activeFilter={severityFilter} onCardClick={setSeverityFilter} />

        <IncidentOverview overview={incidentOverview} activeSeverity={incidentSeverityFilter} activeStatus={incidentStatusFilter} onSelect={setIncidentFilters} />

        <IncidentTable incidents={incidents} onSelect={selectIncident} severityFilter={incidentSeverityFilter} statusFilter={incidentStatusFilter} onClearFilter={(severity, status) => { setIncidentSeverityFilter(severity); setIncidentStatusFilter(status); }} />

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="xl:col-span-2">
            <TrafficChart data={traffic} />
          </div>
          <div>
            <DetectionSummary stats={stats} />
          </div>
        </div>

        <AlertTable
          alerts={alerts}
          onAlertClick={handleAlertClick}
          filterSeverity={severityFilter}
          onClearFilter={() => setSeverityFilter(null)}
        />

        <DevicesTable devices={devices} />
        </> : view === 'controls' ? <>
          <div>
            <h2 className="text-2xl font-bold">Rules &amp; Controls</h2>
            <p className="mt-1 text-sm text-cyber-400">Configuration and analyst actions are kept separate from live monitoring.</p>
          </div>
          <SecurityControls rules={rules} trusted={trustedDevices} suppressions={suppressions} activity={activity} network={network} captureStatus={captureStatus} onRefresh={refresh} onSaveNetwork={saveNetwork} onSaveRule={saveRule} onAddTrusted={addTrusted} onDeleteTrusted={deleteTrusted} onAddSuppression={addSuppression} />
        </> : <>
          <ThreatIntelligence stats={tiStats} indicators={tiIndicators} matches={tiMatches} investigations={aiInvestigations} onCreate={addTi} onUpdate={() => {}} onDisable={disableTi} onImport={importTi} onInvestigate={investigateAi} />
        </>}
      </main>

      {selectedAlert && (
        <AlertDetail
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onStatusChange={handleStatusChange}
        />
      )}
      {selectedIncident && <IncidentDetail incident={selectedIncident} onClose={() => setSelectedIncident(null)} onAction={updateIncident} />}
    </div>
  );
}

function NavButton({ active, onClick, children }) {
  return <button type="button" onClick={onClick} className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${active ? 'border-cyber-accent text-cyber-accent' : 'border-transparent text-cyber-400 hover:text-white'}`}>{children}</button>;
}
