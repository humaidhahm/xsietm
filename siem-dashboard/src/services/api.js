// Base URL of the XSIEM FastAPI backend.
// Override with REACT_APP_API_BASE in .env (CRA only exposes REACT_APP_* vars to the browser).
// Use the Kali VM's LAN address when the dashboard is opened from a different machine.
const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:4000";
const BASE = `${API_BASE}/api`;

async function request(path, params = {}, options = {}) {
  const query = new URLSearchParams(params).toString();
  const url = query ? `${BASE}${path}?${query}` : `${BASE}${path}`;
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export const api = {
  getAlerts: (params) => request("/alerts", params),
  getStats:  ()       => request("/stats"),
  getAgents: ()       => request("/agents"),
  testEmail: ()       => request("/test-email", {}, { method: "POST" }),
  health:    ()       => fetch(`${API_BASE}/health`).then((r) => r.json()),
};

export { API_BASE };
