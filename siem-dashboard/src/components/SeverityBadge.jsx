// ─────────────────────────────────────────────────────────────
//  SeverityBadge — color-coded pill for alert severity
// ─────────────────────────────────────────────────────────────

const SEV_STYLES = {
  high: {
    bg: "rgba(255,59,92,0.12)",
    color: "#ff3b5c",
    border: "rgba(255,59,92,0.3)",
  },
  medium: {
    bg: "rgba(255,140,0,0.12)",
    color: "#ff8c00",
    border: "rgba(255,140,0,0.3)",
  },
  low: {
    bg: "rgba(255,215,0,0.12)",
    color: "#ffd700",
    border: "rgba(255,215,0,0.3)",
  },
};

export default function SeverityBadge({ severity }) {
  const s = SEV_STYLES[severity] || SEV_STYLES.low;
  return (
    <span
      style={{
        background: s.bg,
        color: s.color,
        border: `1px solid ${s.border}`,
        padding: "2px 10px",
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: "0.08em",
        fontFamily: "var(--font-mono)",
        whiteSpace: "nowrap",
      }}
    >
      {severity}
    </span>
  );
}

export { SEV_STYLES };
