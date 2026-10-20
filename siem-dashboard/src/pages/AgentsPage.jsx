// ─────────────────────────────────────────────────────────────
//  AgentsPage — shows all connected Wazuh agents
// ─────────────────────────────────────────────────────────────

export default function AgentsPage({ agents = [] }) {
  const active   = agents.filter((a) => a.status === "active").length;
  const inactive = agents.filter((a) => a.status !== "active").length;

  return (
    <div style={{
      height: "100%", overflowY: "auto",
      padding: 24, display: "flex", flexDirection: "column", gap: 20,
    }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontFamily: "var(--font-display)", fontSize: 22, fontWeight: 800 }}>Agents</div>
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 3 }}>
            Wazuh agents connected to your manager
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <div style={{
            background: "rgba(0,230,118,0.1)", border: "1px solid rgba(0,230,118,0.2)",
            borderRadius: 8, padding: "10px 18px", textAlign: "center",
          }}>
            <div style={{ fontSize: 22, fontWeight: 800, color: "var(--green)", fontFamily: "var(--font-display)" }}>{active}</div>
            <div style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.1em" }}>ACTIVE</div>
          </div>
          <div style={{
            background: "rgba(255,59,92,0.1)", border: "1px solid rgba(255,59,92,0.2)",
            borderRadius: 8, padding: "10px 18px", textAlign: "center",
          }}>
            <div style={{ fontSize: 22, fontWeight: 800, color: "var(--red)", fontFamily: "var(--font-display)" }}>{inactive}</div>
            <div style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.1em" }}>INACTIVE</div>
          </div>
        </div>
      </div>

      {/* Agent cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: 14 }}>
        {agents.map((agent) => {
          const isActive = agent.status === "active";
          return (
            <div key={agent.id} style={{
              background: "var(--surface)",
              border: `1px solid ${isActive ? "rgba(0,230,118,0.2)" : "var(--border)"}`,
              borderRadius: 10,
              padding: 20,
              position: "relative",
              overflow: "hidden",
              animation: "fadeIn 0.4s ease",
            }}>
              {/* Top accent */}
              <div style={{
                position: "absolute", top: 0, left: 0, right: 0, height: 2,
                background: isActive ? "var(--green)" : "var(--muted)",
              }} />

              {/* Agent header */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{
                    width: 36, height: 36,
                    background: isActive ? "rgba(0,230,118,0.12)" : "rgba(255,255,255,0.04)",
                    border: `1px solid ${isActive ? "rgba(0,230,118,0.3)" : "var(--border)"}`,
                    borderRadius: 8,
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                      stroke={isActive ? "#00e676" : "#4a6080"} strokeWidth="2">
                      <rect x="2" y="3" width="20" height="14" rx="2" />
                      <line x1="8" y1="21" x2="16" y2="21" />
                      <line x1="12" y1="17" x2="12" y2="21" />
                    </svg>
                  </div>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text)" }}>{agent.name}</div>
                    <div style={{ fontSize: 10, color: "var(--muted)" }}>ID: {agent.id}</div>
                  </div>
                </div>
                <span style={{
                  background: isActive ? "rgba(0,230,118,0.12)" : "rgba(255,59,92,0.1)",
                  color: isActive ? "var(--green)" : "var(--red)",
                  border: `1px solid ${isActive ? "rgba(0,230,118,0.3)" : "rgba(255,59,92,0.3)"}`,
                  padding: "3px 10px", borderRadius: 4,
                  fontSize: 10, fontWeight: 700, letterSpacing: "0.08em",
                }}>
                  {agent.status?.toUpperCase()}
                </span>
              </div>

              {/* Agent details */}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {[
                  ["IP Address", agent.ip],
                  ["OS", agent.os],
                  ["Version", agent.version],
                  ["Last Seen", agent.lastSeen ? new Date(agent.lastSeen).toLocaleString() : "N/A"],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
                    <span style={{ color: "var(--muted)" }}>{k}</span>
                    <span style={{
                      color: k === "IP Address" ? "var(--accent)" : "var(--text)",
                      fontFamily: "var(--font-mono)",
                      maxWidth: 180,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      textAlign: "right",
                    }}>{v || "N/A"}</span>
                  </div>
                ))}
              </div>

              {/* Active pulse indicator */}
              {isActive && (
                <div style={{
                  position: "absolute", bottom: 14, right: 14,
                  display: "flex", alignItems: "center", gap: 5,
                  fontSize: 9, color: "var(--green)",
                }}>
                  <div style={{
                    width: 5, height: 5, background: "var(--green)",
                    borderRadius: "50%", animation: "pulse 2s infinite",
                  }} />
                  LIVE
                </div>
              )}
            </div>
          );
        })}
      </div>

      {agents.length === 0 && (
        <div style={{
          padding: 60, textAlign: "center",
          color: "var(--muted)", fontSize: 13,
        }}>
          No agents connected yet. Install the Wazuh agent on your target machines.
        </div>
      )}
    </div>
  );
}
