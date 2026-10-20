// ─────────────────────────────────────────────────────────────
//  AlertDetailPanel — slide-in panel for alert details
// ─────────────────────────────────────────────────────────────

import { useState } from "react";
import SeverityBadge from "./SeverityBadge";
import StatusBadge from "./StatusBadge";

export default function AlertDetailPanel({ alert, onClose }) {
  const [resolved, setResolved] = useState(alert.status === "closed");

  if (!alert) return null;

  return (
    <div
      style={{
        width: 400,
        background: "var(--surface)",
        borderLeft: "1px solid var(--border)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        animation: "slideIn 0.3s ease",
        flexShrink: 0,
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "14px 20px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexShrink: 0,
        }}
      >
        <span style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.12em", fontWeight: 600 }}>
          ALERT DETAIL
        </span>
        <button
          onClick={onClose}
          style={{
            background: "none",
            border: "none",
            color: "var(--muted)",
            cursor: "pointer",
            fontSize: 20,
            lineHeight: 1,
            padding: "0 4px",
          }}
        >
          ×
        </button>
      </div>

      {/* Body */}
      <div
        style={{
          flex: 1,
          overflowY: "auto",
          padding: 20,
          display: "flex",
          flexDirection: "column",
          gap: 18,
        }}
      >
        {/* Rule + badges */}
        <div>
          <div
            style={{
              fontFamily: "var(--font-display)",
              fontSize: 15,
              fontWeight: 700,
              color: "var(--text)",
              marginBottom: 10,
              lineHeight: 1.4,
            }}
          >
            {alert.rule}
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={resolved ? "closed" : alert.status} />
          </div>
        </div>

        {/* Metadata grid */}
        <div
          style={{
            background: "var(--bg)",
            borderRadius: 8,
            padding: 14,
            display: "flex",
            flexDirection: "column",
            gap: 10,
          }}
        >
          {[
            ["Time", alert.timestamp],
            ["Source IP", alert.src_ip],
            ["Destination IP", alert.dst_ip],
            ["Agent", alert.agent],
          ].map(([k, v]) => (
            <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
              <span style={{ color: "var(--muted)" }}>{k}</span>
              <span
                style={{
                  color: k.includes("IP") ? "var(--accent)" : "var(--text)",
                  fontFamily: "var(--font-mono)",
                  fontWeight: k.includes("IP") ? 600 : 400,
                }}
              >
                {v}
              </span>
            </div>
          ))}
        </div>

        {/* Description */}
        <div>
          <div
            style={{
              fontSize: 10,
              color: "var(--muted)",
              letterSpacing: "0.12em",
              marginBottom: 8,
              fontWeight: 600,
            }}
          >
            RULE DESCRIPTION
          </div>
          <div style={{ fontSize: 12, color: "var(--text)", lineHeight: 1.7 }}>{alert.desc}</div>
        </div>

        {/* Raw log */}
        <div>
          <div
            style={{
              fontSize: 10,
              color: "var(--muted)",
              letterSpacing: "0.12em",
              marginBottom: 8,
              fontWeight: 600,
            }}
          >
            FULL LOG MESSAGE
          </div>
          <pre
            style={{
              background: "var(--bg)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: 12,
              fontSize: 10,
              color: "#7dd3fc",
              overflowX: "auto",
              whiteSpace: "pre-wrap",
              lineHeight: 1.7,
              fontFamily: "var(--font-mono)",
            }}
          >
            {alert.log}
          </pre>
        </div>

        {/* Action button */}
        <button
          onClick={() => setResolved(!resolved)}
          style={{
            background: resolved
              ? "rgba(0,230,118,0.1)"
              : "linear-gradient(135deg,#ff3b5c,#ff1744)",
            border: resolved ? "1px solid rgba(0,230,118,0.4)" : "none",
            color: resolved ? "#00e676" : "white",
            borderRadius: 8,
            padding: "11px 16px",
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            fontWeight: 700,
            cursor: "pointer",
            letterSpacing: "0.05em",
            transition: "all 0.2s",
            marginTop: 4,
          }}
        >
          {resolved ? "✓ Marked as Resolved" : "Mark as Resolved"}
        </button>
      </div>
    </div>
  );
}
