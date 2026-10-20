// ─────────────────────────────────────────────────────────────
//  InvestigationPage — incident report + timeline + notes
// ─────────────────────────────────────────────────────────────

import { useState } from "react";
import { INVESTIGATION_DATA } from "../data/mockAlerts";

const SEV_COLOR = { high: "#ff3b5c", medium: "#ff8c00", low: "#ffd700", critical: "#ff3b5c" };

export default function InvestigationPage() {
  const [notes, setNotes] = useState(INVESTIGATION_DATA.notes);
  const [saved, setSaved] = useState(false);

  function handleSave() {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <div
      style={{
        height: "100%",
        overflowY: "auto",
        padding: 24,
        display: "flex",
        flexDirection: "column",
        gap: 20,
      }}
    >
      <div style={{ maxWidth: 920 }}>
        {/* Title row */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            gap: 16,
            flexWrap: "wrap",
          }}
        >
          <div>
            <div
              style={{
                fontFamily: "var(--font-display)",
                fontSize: 20,
                fontWeight: 800,
                marginBottom: 6,
                lineHeight: 1.3,
              }}
            >
              {INVESTIGATION_DATA.title}
            </div>
            <div style={{ fontSize: 12, color: "var(--muted)" }}>
              Analyst: {INVESTIGATION_DATA.analyst} &nbsp;·&nbsp; Started: {INVESTIGATION_DATA.started}
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
            <span
              style={{
                background: "rgba(255,59,92,0.15)",
                color: "#ff3b5c",
                border: "1px solid rgba(255,59,92,0.3)",
                padding: "5px 14px",
                borderRadius: 6,
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
              }}
            >
              {INVESTIGATION_DATA.severity}
            </span>
            <span
              style={{
                background: "rgba(255,59,92,0.08)",
                color: "#ff3b5c",
                border: "1px solid rgba(255,59,92,0.2)",
                padding: "5px 14px",
                borderRadius: 6,
                fontSize: 11,
                fontWeight: 600,
                animation: "pulse 2s infinite",
              }}
            >
              {INVESTIGATION_DATA.status.toUpperCase()}
            </span>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 18, marginTop: 20 }}>
          {/* Description */}
          <div
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 10,
              padding: 20,
            }}
          >
            <div
              style={{
                fontSize: 10,
                color: "var(--muted)",
                letterSpacing: "0.12em",
                fontWeight: 600,
                marginBottom: 10,
              }}
            >
              INCIDENT DESCRIPTION
            </div>
            <div style={{ fontSize: 13, color: "var(--text)", lineHeight: 1.8 }}>
              {INVESTIGATION_DATA.description}
            </div>
          </div>

          {/* Two-column: timeline + metadata */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 260px", gap: 18 }}>
            {/* Timeline */}
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
                  padding: "12px 20px",
                  borderBottom: "1px solid var(--border)",
                  fontSize: 10,
                  color: "var(--muted)",
                  letterSpacing: "0.12em",
                  fontWeight: 600,
                }}
              >
                TIMELINE OF EVENTS
              </div>
              <div style={{ padding: "20px 20px 12px" }}>
                {INVESTIGATION_DATA.events.map((e, i) => (
                  <div key={i} style={{ display: "flex", gap: 14, position: "relative" }}>
                    {/* Spine */}
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "center",
                        width: 16,
                        flexShrink: 0,
                      }}
                    >
                      <div
                        style={{
                          width: 10,
                          height: 10,
                          background: SEV_COLOR[e.type],
                          borderRadius: "50%",
                          marginTop: 4,
                          boxShadow: `0 0 8px ${SEV_COLOR[e.type]}88`,
                          flexShrink: 0,
                        }}
                      />
                      {i < INVESTIGATION_DATA.events.length - 1 && (
                        <div
                          style={{
                            width: 1,
                            flex: 1,
                            background: "var(--border)",
                            minHeight: 28,
                            marginTop: 4,
                          }}
                        />
                      )}
                    </div>
                    {/* Content */}
                    <div style={{ paddingBottom: i < INVESTIGATION_DATA.events.length - 1 ? 22 : 8 }}>
                      <span
                        style={{
                          fontSize: 11,
                          color: "var(--accent)",
                          fontFamily: "var(--font-mono)",
                          fontWeight: 700,
                        }}
                      >
                        {e.time}
                      </span>
                      <span style={{ fontSize: 12, color: "var(--text)", marginLeft: 12, lineHeight: 1.5 }}>
                        {e.desc}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Metadata card */}
            <div
              style={{
                background: "var(--surface)",
                border: "1px solid var(--border)",
                borderRadius: 10,
                padding: 20,
                display: "flex",
                flexDirection: "column",
                gap: 14,
              }}
            >
              <div style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.12em", fontWeight: 600 }}>
                INCIDENT METADATA
              </div>
              {[
                ["ID", "APT-2025-03"],
                ["Priority", "P1 — Critical"],
                ["Status", INVESTIGATION_DATA.status],
                ["Analyst", "A. Rahman"],
                ["Started", INVESTIGATION_DATA.started],
                ["Last Update", "2025-03-28 11:15"],
                ["Hosts Affected", "5"],
                ["Data at Risk", "~3.2 GB"],
              ].map(([k, v]) => (
                <div key={k} style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <span style={{ fontSize: 10, color: "var(--muted)" }}>{k}</span>
                  <span
                    style={{
                      fontSize: 12,
                      color: k === "Priority" || k === "Status" ? "#ff3b5c" : "var(--text)",
                      fontFamily: "var(--font-mono)",
                      fontWeight: 500,
                    }}
                  >
                    {v}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Analyst notes */}
          <div
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 10,
              padding: 20,
            }}
          >
            <div
              style={{
                fontSize: 10,
                color: "var(--muted)",
                letterSpacing: "0.12em",
                fontWeight: 600,
                marginBottom: 12,
              }}
            >
              ANALYST NOTES
            </div>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              style={{
                width: "100%",
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "12px 14px",
                color: "var(--text)",
                fontSize: 12,
                fontFamily: "var(--font-mono)",
                resize: "vertical",
                minHeight: 110,
                outline: "none",
                lineHeight: 1.7,
                transition: "border-color 0.2s",
              }}
              onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
              onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
            />
            <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
              <button
                onClick={handleSave}
                style={{
                  background: saved
                    ? "rgba(0,230,118,0.15)"
                    : "linear-gradient(135deg,#0077ff,#00d4ff)",
                  border: saved ? "1px solid rgba(0,230,118,0.4)" : "none",
                  color: saved ? "#00e676" : "white",
                  borderRadius: 6,
                  padding: "9px 20px",
                  fontFamily: "var(--font-mono)",
                  fontSize: 12,
                  fontWeight: 700,
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                {saved ? "✓ Notes Saved" : "Save Notes"}
              </button>
              <button
                style={{
                  background: "transparent",
                  border: "1px solid var(--border)",
                  color: "var(--muted)",
                  borderRadius: 6,
                  padding: "9px 20px",
                  fontFamily: "var(--font-mono)",
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: "pointer",
                }}
              >
                Export Report
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
