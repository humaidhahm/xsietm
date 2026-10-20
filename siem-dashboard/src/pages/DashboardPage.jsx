// ─────────────────────────────────────────────────────────────
//  DashboardPage — overview with stat cards + charts + table
// ─────────────────────────────────────────────────────────────

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  CartesianGrid,
} from "recharts";
import { TIMELINE_DATA } from "../data/mockAlerts";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";

const CHART_TOOLTIP_STYLE = {
  background: "#111827",
  border: "1px solid #1e2d45",
  borderRadius: 6,
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  color: "#e2e8f0",
};

function StatCard({ label, value, color, icon }) {
  return (
    <div
      style={{
        background: "var(--surface)",
        border: `1px solid ${color}33`,
        borderRadius: 10,
        padding: "18px 20px",
        position: "relative",
        overflow: "hidden",
        animation: "fadeIn 0.4s ease",
      }}
    >
      {/* Top accent bar */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 2,
          background: color,
        }}
      />
      <div style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.1em", marginBottom: 8, fontWeight: 600 }}>
        {label}
      </div>
      <div
        style={{
          fontSize: 36,
          fontWeight: 800,
          fontFamily: "var(--font-display)",
          color,
          lineHeight: 1,
        }}
      >
        {value}
      </div>
      {/* Background icon */}
      <div
        style={{
          position: "absolute",
          right: 14,
          top: "50%",
          transform: "translateY(-50%)",
          opacity: 0.12,
          color,
        }}
      >
        {icon}
      </div>
    </div>
  );
}

export default function DashboardPage({ alerts, stats, setPage, setSelectedAlert }) {
  // Use real stats from API if available, otherwise count from alerts array
    const total  = stats?.total  ?? alerts.length;
    const high   = stats?.high   ?? alerts.filter((a) => a.severity === "high").length;
    const med    = stats?.medium ?? alerts.filter((a) => a.severity === "medium").length;
    const low    = stats?.low    ?? alerts.filter((a) => a.severity === "low").length;

  const pieData = [
    { name: "High", value: high },
    { name: "Medium", value: med },
    { name: "Low", value: low },
  ];
  const PIE_COLORS = ["#ff3b5c", "#ff8c00", "#ffd700"];

  return (
    <div
      style={{
        padding: 24,
        display: "flex",
        flexDirection: "column",
        gap: 20,
        overflowY: "auto",
        height: "100%",
      }}
    >
      {/* Page title */}
      <div>
        <div style={{ fontFamily: "var(--font-display)", fontSize: 22, fontWeight: 800, letterSpacing: "0.02em" }}>
          Security Overview
        </div>
        <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 3 }}>
          2025-03-28 · Wazuh SIEM · All agents
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14 }}>
        <StatCard
          label="TOTAL ALERTS"
          value={total}
          color="var(--accent)"
          icon={
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
            </svg>
          }
        />
        <StatCard
          label="HIGH SEVERITY"
          value={high}
          color="#ff3b5c"
          icon={
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
          }
        />
        <StatCard
          label="MEDIUM SEVERITY"
          value={med}
          color="#ff8c00"
          icon={
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          }
        />
        <StatCard
          label="LOW SEVERITY"
          value={low}
          color="#ffd700"
          icon={
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <polyline points="22 4 12 14.01 9 11.01" />
            </svg>
          }
        />
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 290px", gap: 14 }}>
        {/* Timeline bar chart */}
        <div
          style={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 10,
            padding: 20,
          }}
        >
          <div style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.1em", marginBottom: 16, fontWeight: 600 }}>
            ALERT TIMELINE — TODAY
          </div>
          <ResponsiveContainer width="100%" height={170}>
            <BarChart data={TIMELINE_DATA} barSize={10} barGap={2}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d45" vertical={false} />
              <XAxis
                dataKey="time"
                tick={{ fill: "#4a6080", fontSize: 10, fontFamily: "var(--font-mono)" }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "#4a6080", fontSize: 10, fontFamily: "var(--font-mono)" }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              <Bar dataKey="high" name="High" fill="#ff3b5c" radius={[3, 3, 0, 0]} />
              <Bar dataKey="medium" name="Medium" fill="#ff8c00" radius={[3, 3, 0, 0]} />
              <Bar dataKey="low" name="Low" fill="#ffd700" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Pie chart */}
        <div
          style={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 10,
            padding: 20,
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.1em", marginBottom: 8, fontWeight: 600 }}>
            SEVERITY SPLIT
          </div>
          <ResponsiveContainer width="100%" height={140}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={42} outerRadius={62} dataKey="value" paddingAngle={4}>
                {pieData.map((_, i) => (
                  <Cell key={i} fill={PIE_COLORS[i]} />
                ))}
              </Pie>
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", justifyContent: "center", gap: 14, marginTop: 4 }}>
            {pieData.map((d, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "var(--muted)" }}>
                <div style={{ width: 8, height: 8, background: PIE_COLORS[i], borderRadius: 2 }} />
                {d.name} ({d.value})
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent alerts table */}
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
            padding: "14px 20px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.1em", fontWeight: 600 }}>
            RECENT ALERTS
          </span>
          <button
            onClick={() => setPage("alerts")}
            style={{
              fontSize: 11,
              color: "var(--accent)",
              background: "none",
              border: "none",
              cursor: "pointer",
              fontFamily: "var(--font-mono)",
              fontWeight: 600,
            }}
          >
            View all →
          </button>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border)" }}>
              {["TIMESTAMP", "ALERT RULE", "SEVERITY", "SOURCE IP", "STATUS"].map((h) => (
                <th
                  key={h}
                  style={{
                    padding: "10px 16px",
                    textAlign: "left",
                    fontSize: 10,
                    color: "var(--muted)",
                    letterSpacing: "0.1em",
                    fontWeight: 600,
                  }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {alerts.slice(0, 6).map((a) => (
              <tr
                key={a.id}
                onClick={() => {
                  setSelectedAlert(a);
                  setPage("alerts");
                }}
                style={{ borderBottom: "1px solid var(--border)", cursor: "pointer", transition: "background 0.15s" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(0,212,255,0.04)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <td style={{ padding: "10px 16px", color: "var(--muted)", fontFamily: "var(--font-mono)", whiteSpace: "nowrap" }}>
                  {a.timestamp}
                </td>
                <td style={{ padding: "10px 16px", color: "var(--text)", maxWidth: 220 }}>
                  <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.rule}</div>
                </td>
                <td style={{ padding: "10px 16px" }}>
                  <SeverityBadge severity={a.severity} />
                </td>
                <td style={{ padding: "10px 16px", color: "var(--accent)", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                  {a.src_ip}
                </td>
                <td style={{ padding: "10px 16px" }}>
                  <StatusBadge status={a.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
