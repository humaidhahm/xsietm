// ─────────────────────────────────────────────────────────────
//  StatusBadge — Open / Closed indicator
// ─────────────────────────────────────────────────────────────

export default function StatusBadge({ status }) {
  const isOpen = status === "open";
  return (
    <span
      style={{
        background: isOpen ? "rgba(255,59,92,0.1)" : "rgba(0,230,118,0.1)",
        color: isOpen ? "#ff3b5c" : "#00e676",
        border: `1px solid ${isOpen ? "rgba(255,59,92,0.3)" : "rgba(0,230,118,0.3)"}`,
        padding: "2px 10px",
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 600,
        fontFamily: "var(--font-mono)",
        whiteSpace: "nowrap",
        letterSpacing: "0.05em",
      }}
    >
      {status.toUpperCase()}
    </span>
  );
}
