// ─────────────────────────────────────────────────────────────
//  LogsPage — raw Wazuh log stream view
// ─────────────────────────────────────────────────────────────

import { useState } from "react";
import SeverityBadge from "../components/SeverityBadge";

const SEV_COLOR = { high: "#ff3b5c", medium: "#ff8c00", low: "#ffd700" };

export default function LogsPage({ alerts }) {
  const [expandedId, setExpandedId] = useState(null);
  const [search, setSearch] = useState("");

  const filtered = alerts.filter(
    (a) =>
      !search ||
      a.rule.toLowerCase().includes(search.toLowerCase()) ||
      a.src_ip.includes(search) ||
      a.agent.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Header */}
      <div
        style={{
          padding: "16px 24px",
          borderBottom: "1px solid var(--border)",
          background: "var(--surface)",
          display: "flex",
          alignItems: "center",
          gap: 16,
          flexShrink: 0,
        }}
      >
        <div style={{ fontFamily: "var(--font-display)", fontSize: 18, fontWeight: 800 }}>Logs</div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            fontSize: 11,
            color: "var(--green)",
            background: "rgba(0,230,118,0.08)",
            border: "1px solid rgba(0,230,118,0.2)",
            borderRadius: 20,
            padding: "3px 10px",
          }}
        >
          <div
            style={{
              width: 6,
              height: 6,
              background: "var(--green)",
              borderRadius: "50%",
              animation: "pulse 2s infinite",
            }}
          />
          LIVE STREAM
        </div>
        <div style={{ flex: 1 }} />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search logs..."
          style={{
            background: "var(--bg)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "6px 12px",
            color: "var(--text)",
            fontSize: 12,
            fontFamily: "var(--font-mono)",
            outline: "none",
            width: 220,
          }}
          onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
          onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
        />
      </div>

      {/* Log stream */}
      <div style={{ flex: 1, overflowY: "auto", padding: 24 }}>
        <div
          style={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 10,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              padding: "10px 16px",
              borderBottom: "1px solid var(--border)",
              fontSize: 10,
              color: "var(--muted)",
              letterSpacing: "0.1em",
              fontWeight: 600,
              display: "flex",
              justifyContent: "space-between",
            }}
          >
            <span>WAZUH EVENT LOG — {filtered.length} EVENTS</span>
            <span>Click row to expand full log</span>
          </div>

          {filtered.map((a, idx) => {
            const isExpanded = expandedId === a.id;
            return (
              <div
                key={a.id}
                onClick={() => setExpandedId(isExpanded ? null : a.id)}
                style={{
                  borderBottom: idx < filtered.length - 1 ? "1px solid var(--border)" : "none",
                  cursor: "pointer",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => {
                  if (!isExpanded) e.currentTarget.style.background = "rgba(0,212,255,0.02)";
                }}
                onMouseLeave={(e) => {
                  if (!isExpanded) e.currentTarget.style.background = "transparent";
                }}
              >
                {/* Summary row */}
                <div
                  style={{
                    padding: "12px 16px",
                    display: "flex",
                    gap: 14,
                    alignItems: "flex-start",
                    background: isExpanded ? "rgba(0,212,255,0.04)" : "transparent",
                  }}
                >
                  {/* Severity dot */}
                  <div
                    style={{
                      width: 8,
                      height: 8,
                      background: SEV_COLOR[a.severity],
                      borderRadius: "50%",
                      marginTop: 4,
                      flexShrink: 0,
                      boxShadow: `0 0 6px ${SEV_COLOR[a.severity]}88`,
                    }}
                  />
                  <span
                    style={{
                      color: "var(--muted)",
                      fontSize: 11,
                      whiteSpace: "nowrap",
                      fontFamily: "var(--font-mono)",
                      marginTop: 2,
                    }}
                  >
                    {a.timestamp}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: 12,
                        color: SEV_COLOR[a.severity],
                        fontWeight: 600,
                        marginBottom: 4,
                      }}
                    >
                      [{a.severity.toUpperCase()}] {a.rule}
                    </div>
                    <div
                      style={{
                        fontSize: 10,
                        color: "#7dd3fc",
                        fontFamily: "var(--font-mono)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {a.log.split("\n")[0]}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
                    <span style={{ fontSize: 10, color: "var(--muted)" }}>{a.agent}</span>
                    <SeverityBadge severity={a.severity} />
                    <span style={{ color: "var(--muted)", fontSize: 14 }}>{isExpanded ? "▲" : "▼"}</span>
                  </div>
                </div>

                {/* Expanded raw log */}
                {isExpanded && (
                  <div style={{ padding: "0 16px 16px 38px" }}>
                    <pre
                      style={{
                        background: "var(--bg)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        padding: 14,
                        fontSize: 11,
                        color: "#7dd3fc",
                        whiteSpace: "pre-wrap",
                        lineHeight: 1.8,
                        fontFamily: "var(--font-mono)",
                        margin: 0,
                      }}
                    >
                      {a.log}
                    </pre>
                    <div
                      style={{
                        display: "flex",
                        gap: 16,
                        marginTop: 10,
                        fontSize: 11,
                        color: "var(--muted)",
                      }}
                    >
                      <span>
                        <span style={{ color: "var(--accent)" }}>src:</span> {a.src_ip}
                      </span>
                      <span>
                        <span style={{ color: "var(--accent)" }}>dst:</span> {a.dst_ip}
                      </span>
                      <span>
                        <span style={{ color: "var(--accent)" }}>agent:</span> {a.agent}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
