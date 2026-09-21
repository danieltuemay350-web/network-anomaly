const API_BASE = '/api';

async function fetchJSON(url, options = {}) {
  const res = await fetch(`${API_BASE}${url}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) {
    let detail = '';
    try {
      const body = await res.json();
      detail = typeof body.detail === 'string' ? body.detail : '';
    } catch (_) {
      // A proxy/network error may not include a JSON API body.
    }
    throw new Error(detail || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  health: () => fetchJSON('/health'),
  stats: () => fetchJSON('/stats'),
  alerts: (params = {}) => {
    const qs = new URLSearchParams();
    if (params.skip) qs.set('skip', params.skip);
    if (params.limit) qs.set('limit', params.limit);
    if (params.alert_type) qs.set('alert_type', params.alert_type);
    if (params.severity) qs.set('severity', params.severity);
    if (params.status) qs.set('status', params.status);
    const q = qs.toString();
    return fetchJSON(`/alerts${q ? `?${q}` : ''}`);
  },
  alert: (id) => fetchJSON(`/alerts/${id}`),
  updateAlert: (id, status) =>
    fetchJSON(`/alerts/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  devices: () => fetchJSON('/devices'),
  traffic: (limit = 60) => fetchJSON(`/traffic?limit=${limit}`),
  captureStatus: () => fetchJSON('/capture/status'),
  incidents: (params = {}) => {
    const qs = new URLSearchParams();
    if (params.status) qs.set('status', params.status);
    if (params.limit) qs.set('limit', params.limit);
    const q = qs.toString();
    return fetchJSON(`/incidents${q ? `?${q}` : ''}`);
  },
  incident: (id) => fetchJSON(`/incidents/${id}`),
  acknowledgeIncident: (id) => fetchJSON(`/incidents/${id}/acknowledge`, { method: 'POST' }),
  resolveIncident: (id) => fetchJSON(`/incidents/${id}/resolve`, { method: 'POST' }),
  analytics: () => fetchJSON('/analytics'),
  rules: () => fetchJSON('/rules'),
  updateRule: (type, body) => fetchJSON(`/rules/${type}`, { method: 'PUT', body: JSON.stringify(body) }),
  trustedDevices: () => fetchJSON('/trusted-devices'),
  addTrustedDevice: (body) => fetchJSON('/trusted-devices', { method: 'POST', body: JSON.stringify(body) }),
  deleteTrustedDevice: (id) => fetchJSON(`/trusted-devices/${id}`, { method: 'DELETE' }),
  suppressions: () => fetchJSON('/suppressions'),
  addSuppression: (body) => fetchJSON('/suppressions', { method: 'POST', body: JSON.stringify(body) }),
  activity: () => fetchJSON('/activity'),
  networkInterfaces: () => fetchJSON('/network/interfaces'),
  updateNetworkConfig: (body) => fetchJSON('/network/config', { method: 'PUT', body: JSON.stringify(body) }),
  tiIndicators: (params = {}) => fetchJSON(`/threat-intelligence/indicators?${new URLSearchParams(params)}`),
  createTiIndicator: (body) => fetchJSON('/threat-intelligence/indicators', { method: 'POST', body: JSON.stringify(body) }),
  updateTiIndicator: (id, body) => fetchJSON(`/threat-intelligence/indicators/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
  disableTiIndicator: (id) => fetchJSON(`/threat-intelligence/indicators/${id}`, { method: 'DELETE' }),
  tiMatches: () => fetchJSON('/threat-intelligence/matches'),
  tiStats: () => fetchJSON('/threat-intelligence/stats'),
  importTi: (body) => fetchJSON('/threat-intelligence/import', { method: 'POST', body: JSON.stringify(body) }),
  aiInvestigations: () => fetchJSON('/threat-intelligence/investigations'),
  investigateAi: (body) => fetchJSON('/threat-intelligence/investigations', { method: 'POST', body: JSON.stringify(body) }),
};
