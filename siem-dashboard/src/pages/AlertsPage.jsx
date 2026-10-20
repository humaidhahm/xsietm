// ─────────────────────────────────────────────────────────────
//  AlertsPage — filterable alert table + detail panel
// ─────────────────────────────────────────────────────────────

import { useState, useMemo } from "react";
import SeverityBadge, { SEV_STYLES } from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import AlertDetailPanel from "../components/AlertDetailPanel";

const SEVERITIES = ["all", "high", "medium", "low"];

function FilterButton({ label, active, color, bgColor, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "5px 14px",
        borderRadius: 6,
        border: "1px solid",
        borderColor: active ? color : "var(--border)",
        background: active ? bgColor : "transparent",
        color: active ? color : "var(--muted)",
        fontSize: 11,
        fontFamily: "var(--font-mono)",
        cursor: "pointer",
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.05em",
        transition: "all 0.15s",
      }}
    >
      {label}
    </button>
  );
}

export default function AlertsPage({ alerts, selectedAlert, setSelectedAlert }) {
  const [sevFilter, setSevFilter] = useState("all");
  const [search, setSearch] = useState("");

  const filtered = useMemo(
    () =>
      alerts.filter((a) => {
        const matchSev = sevFilter === "all" || a.severity === sevFilter;
        const matchSearch =
          !search ||
          a.src_ip.includes(search) ||
          a.dst_ip.includes(search) ||
          a.rule.toLowerCase().includes(search.toLowerCase()) ||
          a.agent.toLowerCase().includes(search.toLowerCase());
        return matchSev && matchSearch;
      }),
    [alerts, sevFilter, search]
  );

  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      {/* Table column */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>
        {/* Toolbar */}
        <div
          style={{
            padding: "16px 24px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            gap: 10,
            alignItems: "center",
            flexWrap: "wrap",
            flexShrink: 0,
            background: "var(--surface)",
          }}
        >
          <div style={{ fontFamily: "var(--font-display)", fontSize: 18, fontWeight: 800, marginRight: 4 }}>
            Alerts
          </div>
          <div
            style={{
              fontSize: 12,
              color: "var(--muted)",
              background: "var(--bg)",
              border: "1px solid var(--border)",
              borderRadius: 20,
              padding: "2px 10px",
            }}
          >
            {filtered.length} results
          </div>

          <div style={{ flex: 1 }} />

          {/* Search */}
          <div style={{ position: "relative" }}>
            <svg
              style={{
                position: "absolute",
                left: 10,
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--muted)",
                pointerEvents: "none",
              }}
              width="13"
              height="13"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="IP, rule, agent..."
              style={{
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "6px 12px 6px 30px",
                color: "var(--text)",
                fontSize: 12,
                fontFamily: "var(--font-mono)",
                outline: "none",
                width: 200,
              }}
              onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
              onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
            />
          </div>

          {/* Severity filters */}
          {SEVERITIES.map((s) => {
            const style = s === "all" ? null : SEV_STYLES[s];
            const color = style ? style.color : "var(--accent)";
            const bg = style ? style.bg : "rgba(0,212,255,0.1)";
            return (
              <FilterButton
                key={s}
                label={s}
                active={sevFilter === s}
                color={color}
                bgColor={bg}
                onClick={() => setSevFilter(s)}
              />
            );
          })}
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflowY: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead
              style={{
                position: "sticky",
                top: 0,
                background: "var(--surface)",
                zIndex: 1,
                borderBottom: "1px solid var(--border)",
              }}
            >
              <tr>
                {["TIMESTAMP", "ALERT RULE", "SEV", "SOURCE IP", "DEST IP", "AGENT", "STATUS"].map((h) => (
                  <th
                    key={h}
                    style={{
                      padding: "10px 16px",
                      textAlign: "left",
                      fontSize: 10,
                      color: "var(--muted)",
                      letterSpacing: "0.1em",
                      fontWeight: 600,
                      whiteSpace: "nowrap",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => {
                const isActive = selectedAlert?.id === a.id;
                return (
                  <tr
                    key={a.id}
                    onClick={() => setSelectedAlert(isActive ? null : a)}
                    style={{
                      borderBottom: "1px solid var(--border)",
                      cursor: "pointer",
                      background: isActive ? "rgba(0,212,255,0.06)" : "transparent",
                      transition: "background 0.15s",
                    }}
                    onMouseEnter={(e) => {
                      if (!isActive) e.currentTarget.style.background = "rgba(0,212,255,0.03)";
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive) e.currentTarget.style.background = "transparent";
                    }}
                  >
                    <td style={{ padding: "10px 16px", color: "var(--muted)", whiteSpace: "nowrap" }}>
                      {a.timestamp}
                    </td>
                    <td style={{ padding: "10px 16px", color: "var(--text)", maxWidth: 220 }}>
                      <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {a.rule}
                      </div>
                    </td>
                    <td style={{ padding: "10px 16px" }}>
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td style={{ padding: "10px 16px", color: "var(--accent)", fontWeight: 600 }}>{a.src_ip}</td>
                    <td style={{ padding: "10px 16px", color: "var(--muted)" }}>{a.dst_ip}</td>
                    <td style={{ padding: "10px 16px", color: "var(--muted)" }}>{a.agent}</td>
                    <td style={{ padding: "10px 16px" }}>
                      <StatusBadge status={a.status} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filtered.length === 0 && (
            <div
              style={{
                padding: "60px 0",
                textAlign: "center",
                color: "var(--muted)",
                fontSize: 13,
              }}
            >
              No alerts match your filters.
            </div>
          )}
        </div>
      </div>

      {/* Detail panel */}
      {selectedAlert && (
        <AlertDetailPanel alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      )}
    </div>
  );
}
