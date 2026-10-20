export default function Topbar({ search, setSearch, lastUpdated, refreshing, onRefresh }) {
  return (
    <div style={{
      height: 56,
      background: "var(--surface)",
      borderBottom: "1px solid var(--border)",
      display: "flex",
      alignItems: "center",
      padding: "0 24px",
      gap: 14,
      flexShrink: 0,
    }}>
      {/* Search */}
      <div style={{ flex: 1, position: "relative" }}>
        <svg style={{
          position: "absolute", left: 12, top: "50%",
          transform: "translateY(-50%)", color: "var(--muted)", pointerEvents: "none",
        }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search alerts, IPs, rules..."
          style={{
            width: "100%", maxWidth: 420,
            background: "var(--bg)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "7px 12px 7px 34px",
            color: "var(--text)", fontSize: 12,
            fontFamily: "var(--font-mono)", outline: "none",
          }}
          onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
          onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
        />
      </div>

      {/* Last updated */}
      {lastUpdated && (
        <div style={{ fontSize: 10, color: "var(--muted)", whiteSpace: "nowrap" }}>
          Updated {lastUpdated.toLocaleTimeString()}
        </div>
      )}

      {/* Refresh button */}
      <button
        onClick={onRefresh}
        disabled={refreshing}
        title="Refresh data"
        style={{
          background: "var(--bg)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          color: refreshing ? "var(--muted)" : "var(--accent)",
          cursor: refreshing ? "not-allowed" : "pointer",
          padding: "6px 8px",
          display: "flex",
          alignItems: "center",
          gap: 4,
          fontSize: 11,
          fontFamily: "var(--font-mono)",
        }}
      >
        <svg
          width="13" height="13" viewBox="0 0 24 24" fill="none"
          stroke="currentColor" strokeWidth="2"
          style={{ animation: refreshing ? "spin 1s linear infinite" : "none" }}
        >
          <polyline points="23 4 23 10 17 10" />
          <polyline points="1 20 1 14 7 14" />
          <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
        </svg>
        {refreshing ? "Syncing..." : "Refresh"}
      </button>

      <div style={{ width: 1, height: 24, background: "var(--border)" }} />

      {/* Notification bell */}
      <button style={{
        background: "none", border: "none",
        color: "var(--muted)", cursor: "pointer",
        position: "relative", padding: 4,
      }}>
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
          <path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
        <div style={{
          position: "absolute", top: 2, right: 2,
          width: 7, height: 7,
          background: "#ff3b5c", borderRadius: "50%",
          border: "1.5px solid var(--surface)",
        }} />
      </button>

      {/* User */}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 12, color: "var(--text)", fontWeight: 600 }}>A. Rahman</div>
          <div style={{ fontSize: 10, color: "var(--muted)" }}>SOC Analyst · Tier 2</div>
        </div>
        <div style={{
          width: 34, height: 34,
          background: "linear-gradient(135deg,#0077ff,#00d4ff)",
          borderRadius: "50%",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 13, fontWeight: 700, color: "white",
          fontFamily: "var(--font-display)", flexShrink: 0,
        }}>AR</div>
      </div>
    </div>
  );
}
