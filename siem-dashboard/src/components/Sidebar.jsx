const ShieldIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

const NAV_ICONS = {
  dashboard: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" />
      <rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" />
    </svg>
  ),
  alerts: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  logs: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" />
    </svg>
  ),
  agents: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  ),
  investigation: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  ),
};

const NAV_ITEMS = [
  { key: "dashboard",    label: "Dashboard" },
  { key: "alerts",       label: "Alerts" },
  { key: "logs",         label: "Logs" },
  { key: "agents",       label: "Agents" },
  { key: "investigation",label: "Investigation" },
];

function NavItem({ icon, label, active, onClick, badge }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: "100%",
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "9px 20px",
        background: active ? "rgba(0,212,255,0.08)" : "transparent",
        border: "none",
        borderLeft: active ? "2px solid var(--accent)" : "2px solid transparent",
        color: active ? "var(--accent)" : "var(--muted)",
        cursor: "pointer",
        fontSize: 13,
        fontFamily: "var(--font-mono)",
        fontWeight: active ? 600 : 400,
        transition: "all 0.2s",
        textAlign: "left",
        justifyContent: "flex-start",
      }}
      onMouseEnter={(e) => {
        if (!active) e.currentTarget.style.color = "var(--text)";
      }}
      onMouseLeave={(e) => {
        if (!active) e.currentTarget.style.color = "var(--muted)";
      }}
    >
      {icon}
      <span style={{ flex: 1 }}>{label}</span>
      {badge !== undefined && (
        <span style={{
          background: active ? "rgba(0,212,255,0.2)" : "rgba(255,255,255,0.06)",
          color: active ? "var(--accent)" : "var(--muted)",
          fontSize: 10,
          fontWeight: 700,
          padding: "1px 7px",
          borderRadius: 10,
          minWidth: 20,
          textAlign: "center",
        }}>
          {badge}
        </span>
      )}
    </button>
  );
}

export default function Sidebar({ page, setPage, agents = [], health = null }) {
  const activeAgents = agents.filter((a) => a.status === "active").length;

  // Real system status - derived from GET /health, never hardcoded.
  const wazuhOk = health?.wazuh === "ok";
  const indexer = health?.indexer;
  const indexerOk = indexer === "green" || indexer === "yellow";
  const statusRows = [
    {
      label: "Wazuh Manager",
      color: wazuhOk ? "var(--green)" : "var(--red)",
      status: wazuhOk ? "Online" : "Offline",
    },
    {
      label: `Agents: ${activeAgents} Active`,
      color: activeAgents > 0 ? "var(--green)" : "var(--muted)",
      status: "",
    },
    {
      label: "Indexer (OpenSearch)",
      color: indexerOk ? "var(--green)" : health ? "var(--red)" : "var(--muted)",
      status: indexer ? indexer : "unknown",
    },
  ];

  return (
    <div style={{
      width: 220,
      background: "var(--surface)",
      borderRight: "1px solid var(--border)",
      display: "flex",
      flexDirection: "column",
      flexShrink: 0,
      height: "100%",
    }}>
      {/* Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "18px 20px 14px" }}>
        <div style={{
          width: 34, height: 34,
          background: "linear-gradient(135deg,#00d4ff,#0077ff)",
          borderRadius: 8,
          display: "flex", alignItems: "center", justifyContent: "center",
          boxShadow: "0 0 16px rgba(0,212,255,0.35)",
          flexShrink: 0,
        }}>
          <ShieldIcon />
        </div>
        <div>
          <div style={{
            fontFamily: "var(--font-display)",
            fontWeight: 800, fontSize: 14,
            letterSpacing: "0.05em", color: "var(--text)",
          }}>SIEM</div>
          <div style={{ fontSize: 9, color: "var(--accent)", letterSpacing: "0.14em", fontWeight: 600 }}>
            DASHBOARD v2
          </div>
        </div>
      </div>

      <div style={{ borderTop: "1px solid var(--border)", margin: "0 0 6px" }} />

      <div style={{
        fontSize: 9, color: "var(--muted)",
        padding: "6px 20px 4px",
        letterSpacing: "0.14em", fontWeight: 600,
      }}>NAVIGATION</div>

      {NAV_ITEMS.map(({ key, label }) => (
        <NavItem
          key={key}
          icon={NAV_ICONS[key]}
          label={label}
          active={page === key}
          onClick={() => setPage(key)}
          badge={key === "agents" ? activeAgents : undefined}
        />
      ))}

      <div style={{ flex: 1 }} />

      {/* Threat level indicator */}
      <div style={{
        margin: "0 12px 12px",
        background: "rgba(255,59,92,0.08)",
        border: "1px solid rgba(255,59,92,0.2)",
        borderRadius: 8,
        padding: "10px 12px",
      }}>
        <div style={{ fontSize: 9, color: "var(--muted)", letterSpacing: "0.12em", marginBottom: 6, fontWeight: 600 }}>
          THREAT LEVEL
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ flex: 1, height: 4, background: "var(--border)", borderRadius: 2, overflow: "hidden" }}>
            <div style={{
              width: "65%", height: "100%",
              background: "linear-gradient(90deg,#ffd700,#ff8c00)",
              borderRadius: 2,
            }} />
          </div>
          <span style={{ fontSize: 10, color: "#ff8c00", fontWeight: 700 }}>MEDIUM</span>
        </div>
      </div>

      {/* System status */}
      <div style={{ padding: "12px 20px", borderTop: "1px solid var(--border)" }}>
        <div style={{ fontSize: 9, color: "var(--muted)", marginBottom: 8, letterSpacing: "0.12em", fontWeight: 600 }}>
          SYSTEM STATUS
        </div>
        {statusRows.map(({ label, color, status }) => (
          <div key={label} style={{
            display: "flex", alignItems: "center",
            gap: 6, fontSize: 10, color,
            marginBottom: 5,
          }}>
            <div style={{
              width: 5, height: 5, background: color,
              borderRadius: "50%",
              animation: "pulse 2s infinite",
              flexShrink: 0,
            }} />
            {label} {status && `· ${status}`}
          </div>
        ))}
      </div>
    </div>
  );
}
