import { useState, useEffect, useCallback } from "react";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import DashboardPage from "./pages/DashboardPage";
import AlertsPage from "./pages/AlertsPage";
import LogsPage from "./pages/LogsPage";
import InvestigationPage from "./pages/InvestigationPage";
import AgentsPage from "./pages/AgentsPage";
import { MOCK_ALERTS } from "./data/mockAlerts";
import { api } from "./services/api";

const REFRESH_INTERVAL = 30000; // 30 seconds

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [search, setSearch] = useState("");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [alerts, setAlerts] = useState(MOCK_ALERTS);
  const [agents, setAgents] = useState([]);
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [usingMock, setUsingMock] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [refreshing, setRefreshing] = useState(false);

  const addNotification = useCallback((msg, type = "info") => {
    const id = Date.now();
    setNotifications((prev) => [...prev.slice(-4), { id, msg, type }]);
    setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id));
    }, 4000);
  }, []);

  const fetchData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    try {
      const [alertsRes, agentsRes, statsRes] = await Promise.all([
        api.getAlerts({ limit: 500 }),
        api.getAgents(),
        api.getStats(),
      ]);

      if (alertsRes.data && alertsRes.data.length > 0) {
        // Check for new high severity alerts
        const prevHighCount = alerts.filter((a) => a.severity === "high").length;
        const newHighCount = alertsRes.data.filter((a) => a.severity === "high").length;
        if (isRefresh && newHighCount > prevHighCount) {
          addNotification(
            `🚨 ${newHighCount - prevHighCount} new high severity alert(s) detected!`,
            "danger"
          );
        }
        setAlerts(alertsRes.data);
        setUsingMock(false);
      } else {
        setUsingMock(true);
      }

      if (agentsRes.data) setAgents(agentsRes.data);
      if (statsRes) setStats(statsRes);
      setLastUpdated(new Date());
      // Real system status for the sidebar panel (no hardcoded strings).
      try {
        const h = await api.health();
        if (h) setHealth(h);
      } catch (_) { /* health is best-effort */ }    } catch (err) {
      if (!isRefresh) setUsingMock(true);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [alerts, addNotification]);

  // Initial fetch
  useEffect(() => {
    fetchData(false);
  }, []);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => fetchData(true), REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchData]);

  function navigate(p) {
    setPage(p);
    setSelectedAlert(null);
  }

  const pageContent = () => {
    switch (page) {
      case "dashboard":
        return (
          <DashboardPage
            alerts={alerts}
            agents={agents}
            stats={stats}
            setPage={navigate}
            setSelectedAlert={setSelectedAlert}
          />
        );
      case "alerts":
        return (
          <AlertsPage
            alerts={alerts}
            selectedAlert={selectedAlert}
            setSelectedAlert={setSelectedAlert}
          />
        );
      case "logs":
        return <LogsPage alerts={alerts} />;
      case "agents":
        return <AgentsPage agents={agents} />;
      case "investigation":
        return <InvestigationPage />;
      default:
        return null;
    }
  };

  return (
    <div style={{
      display: "flex",
      height: "100vh",
      overflow: "hidden",
      fontFamily: "var(--font-mono)",
      background: "var(--bg)",
    }}>
      <Sidebar page={page} setPage={navigate} agents={agents} health={health} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>
        <Topbar
          search={search}
          setSearch={setSearch}
          lastUpdated={lastUpdated}
          refreshing={refreshing}
          onRefresh={() => fetchData(true)}
        />

        {/* Status banners */}
        {usingMock && !loading && (
          <div style={{
            background: "rgba(255,140,0,0.08)",
            borderBottom: "1px solid rgba(255,140,0,0.2)",
            padding: "6px 24px",
            fontSize: 11,
            color: "#ff8c00",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}>
            <span>⚠</span>
            Backend connected but no real alerts yet — showing mock data. Run attacks from Kali to see real alerts.
          </div>
        )}

        {loading && (
          <div style={{
            padding: "6px 24px",
            fontSize: 11,
            color: "var(--accent)",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}>
            <div style={{
              width: 6, height: 6,
              background: "var(--accent)",
              borderRadius: "50%",
              animation: "pulse 1s infinite",
            }} />
            Connecting to Wazuh...
          </div>
        )}

        <div style={{ flex: 1, overflow: "hidden", background: "var(--bg)" }}>
          {pageContent()}
        </div>
      </div>

      {/* Toast notifications */}
      <div style={{
        position: "fixed",
        bottom: 24,
        right: 24,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        zIndex: 9999,
      }}>
        {notifications.map((n) => (
          <div
            key={n.id}
            style={{
              background: n.type === "danger" ? "rgba(255,59,92,0.95)" : "rgba(0,212,255,0.95)",
              color: "white",
              padding: "12px 18px",
              borderRadius: 8,
              fontSize: 12,
              fontFamily: "var(--font-mono)",
              fontWeight: 600,
              boxShadow: "0 4px 20px rgba(0,0,0,0.4)",
              animation: "fadeIn 0.3s ease",
              maxWidth: 340,
              backdropFilter: "blur(10px)",
            }}
          >
            {n.msg}
          </div>
        ))}
      </div>
    </div>
  );
}
