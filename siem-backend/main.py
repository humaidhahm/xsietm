from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import httpx, asyncio, smtplib, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# Load .env (same directory as main.py) before reading any settings.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv optional — env vars still work
    pass

app = FastAPI(title="SIEM Dashboard API v2")

# Origins allowed to call the API. Override with CORS_ORIGINS (comma separated).
_default_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://192.168.49.128:3000",  # this Kali VM's LAN address
]
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()] or _default_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Wazuh Config ──────────────────────────────────────────────────────────
# Every credential comes from the environment. A missing secret is a hard,
# obvious failure at import time - never a silent fallback to a default.
def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value or not value.strip():
        raise SystemExit(
            f"[FATAL] Required environment variable {name} is not set.\n"
            f"        The backend auto-loads a .env file from its own directory when one\n"
            f"        exists. Otherwise export it before starting:\n"
            f"            set -a; . ./.env; set +a\n"
            f"        (see README.md - 'cp .env.example .env and fill it in')"
        )
    return value.strip()


WAZUH_HOST = os.getenv("WAZUH_API_HOST", "https://localhost:55000")
WAZUH_USER = require_env("WAZUH_API_USER")
WAZUH_PASS = require_env("WAZUH_API_PASSWORD")
CLIENT_KWARGS = {"verify": False, "timeout": 30.0}

# ── Wazuh Indexer (OpenSearch) Config ─────────────────────────────────────
INDEXER_HOST = os.getenv("XSIEM_INDEXER_URL", "https://localhost:9200")
INDEXER_USER = require_env("WAZUH_INDEXER_USER")
INDEXER_PASS = require_env("WAZUH_INDEXER_PASSWORD")
INDEXER_INDEX = os.getenv("XSIEM_INDEXER_INDEX", "wazuh-alerts-*")

# ── Email Config — optional, set in .env ──────────────────────────────────
EMAIL_SENDER   = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "")
SMTP_HOST      = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT      = int(os.getenv("SMTP_PORT", "587"))

# ── Token Cache ───────────────────────────────────────────────
_token_cache = {"token": None}

# ── Email Alert Tracking (avoid duplicate emails) ─────────────
_alerted_ids = set()

def email_is_configured() -> bool:
    """True only when real SMTP credentials have been supplied."""
    values = (EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECEIVER)
    return all(v and v.strip() for v in values)

async def get_token(force_refresh: bool = False):
    """Return a cached Wazuh API token, or authenticate for a new one.

    force_refresh is used when the manager has restarted (its signing keys change,
    invalidating cached tokens) so we re-authenticate instead of serving a stale
    token.
    """
    if _token_cache["token"] and not force_refresh:
        return _token_cache["token"]
    async with httpx.AsyncClient(**CLIENT_KWARGS) as client:
        r = await client.post(
            f"{WAZUH_HOST}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
        )
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Auth failed: {r.text}")
        token = r.json()["data"]["token"]
        _token_cache["token"] = token
        asyncio.get_running_loop().call_later(
            840, lambda: _token_cache.update({"token": None})
        )
        return token


async def wazuh_api_get(path: str, params: dict | None = None):
    """GET a Wazuh API path, transparently refreshing the token on 401.

    A 401 here almost always means the cached token is stale (the manager was
    restarted), not that the credentials are wrong - so refresh once and retry.
    """
    token = await get_token()
    async with httpx.AsyncClient(**CLIENT_KWARGS) as client:
        r = await client.get(
            f"{WAZUH_HOST}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        )
        if r.status_code == 401:
            token = await get_token(force_refresh=True)
            r = await client.get(
                f"{WAZUH_HOST}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=params,
            )
        return r

# ── Email Alert Function ──────────────────────────────────────
def send_email_alert(alert: dict):
    """Send email for high severity alerts."""
    if not email_is_configured():
        print("[EMAIL SKIPPED] SMTP credentials not configured in .env")
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 SIEM HIGH SEVERITY ALERT: {alert['rule']}"
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER

        html = f"""
        <html>
        <body style="font-family: monospace; background: #070b12; color: #e2e8f0; padding: 24px;">
            <div style="max-width: 600px; margin: 0 auto;">
                <div style="background: #ff3b5c; color: white; padding: 12px 20px; border-radius: 8px 8px 0 0;">
                    <h2 style="margin:0;">🚨 HIGH SEVERITY ALERT DETECTED</h2>
                </div>
                <div style="background: #0d1320; border: 1px solid #1e2d45; padding: 24px; border-radius: 0 0 8px 8px;">
                    <table style="width:100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px 0; color: #4a6080; width: 140px;">Rule</td>
                            <td style="padding: 8px 0; color: #ff3b5c; font-weight: bold;">{alert['rule']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #4a6080;">Severity</td>
                            <td style="padding: 8px 0; color: #ff3b5c; font-weight: bold;">HIGH</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #4a6080;">Source IP</td>
                            <td style="padding: 8px 0; color: #00d4ff;">{alert['src_ip']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #4a6080;">Agent</td>
                            <td style="padding: 8px 0; color: #e2e8f0;">{alert['agent']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #4a6080;">Time</td>
                            <td style="padding: 8px 0; color: #e2e8f0;">{alert['timestamp']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #4a6080;">Description</td>
                            <td style="padding: 8px 0; color: #e2e8f0;">{alert['desc']}</td>
                        </tr>
                    </table>
                    <div style="margin-top: 20px; padding: 12px; background: #111827; border-radius: 6px; border-left: 3px solid #ff3b5c;">
                        <pre style="color: #7dd3fc; font-size: 11px; margin: 0; white-space: pre-wrap;">{str(alert.get('log', ''))[:500]}</pre>
                    </div>
                    <p style="margin-top: 20px; color: #4a6080; font-size: 12px;">
                        This is an automated alert from your SIEM Dashboard.<br>
                        Investigate immediately at your SOC dashboard.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())

        print(f"[EMAIL] Alert sent for: {alert['rule']}")

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


def check_and_alert(alerts: list, background_tasks: BackgroundTasks):
    """Check for high severity alerts and send emails."""
    for alert in alerts:
        alert_id = alert.get("id", "")
        if alert.get("severity") == "high" and alert_id not in _alerted_ids:
            _alerted_ids.add(alert_id)
            background_tasks.add_task(send_email_alert, alert)


# ── Helpers ───────────────────────────────────────────────────
def map_severity(level: int) -> str:
    if level >= 12: return "high"
    if level >= 7:  return "medium"
    return "low"

def format_syscheck(a: dict) -> dict:
    agent_info = a.get("agent", {})
    agent_name = agent_info.get("name", "unknown") if isinstance(agent_info, dict) else "unknown"
    agent_ip   = agent_info.get("ip",   "unknown") if isinstance(agent_info, dict) else "unknown"

    event_type = a.get("type", a.get("result", ""))
    if event_type in ["deleted", "failed"]:
        severity = "high"
    elif event_type in ["modified", "unknown"]:
        severity = "medium"
    else:
        severity = "low"

    file_path = a.get("file", a.get("name", "Unknown"))
    rule = f"File integrity change: {file_path}" if a.get("file") else f"SCA Check: {file_path}"

    return {
        "id":        str(a.get("date", "") or a.get("id", "")),
        "timestamp": a.get("date", a.get("start_scan", "")),
        "rule":      rule,
        "severity":  severity,
        "src_ip":    agent_ip,
        "dst_ip":    "-",
        "agent":     agent_name,
        "status":    "open" if event_type != "passed" else "closed",
        "desc":      a.get("description", rule),
        "log":       str(a)[:500],
        "rule_id":   str(a.get("id", "")),
        "groups":    [],
        "level":     12 if severity == "high" else 7 if severity == "medium" else 3,
    }
def _event_field(src: dict, *paths):
    """Fetch the first present nested field from a decoded Windows event.

    The Wazuh indexer stores the decoded event under data.win.* , e.g.
    data.win.eventdata.ipAddress holds the address that originated the event
    (the attacker for a remote logon). data.win.system.* holds properties of
    the machine that WROTE the event, which is not the source of the activity.
    """
    for path in paths:
        cur = src
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        if cur not in (None, ""):
            return cur
    return None


def _raw_event(src: dict) -> str:
    """Return the raw event body for an alert.

    Correlation (frequency) rules aggregate several events, and Wazuh stores
    the aggregated body in `previous_output` instead of `full_log`. Direct rules
    use `full_log`. Support both so every alert can show its raw event.
    """
    raw = src.get("full_log")
    if raw:
        return raw
    prev = src.get("previous_output")
    if isinstance(prev, str) and prev:
        return prev
    if isinstance(prev, list) and prev:
        return "\n".join(str(p) for p in prev)
    return ""


def format_opensearch_alert(hit: dict) -> dict:
    """Format raw OpenSearch alert to frontend format."""
    src = hit.get("_source", {})
    rule  = src.get("rule",  {})
    agent = src.get("agent", {})
    data  = src.get("data",  {})

    level = rule.get("level", 0)
    if level >= 12:   severity = "high"
    elif level >= 7:  severity = "medium"
    else:             severity = "low"

    # src_ip must come from the EVENT, not from the agent metadata: the agent
    # address is the machine that reported the event (the target), so using it
    # makes a remote attack look like a local one.
    src_ip = _event_field(src, "data.win.eventdata.ipAddress",
                                 "data.win.system.ipAddress") or "-"
    dst_ip = _event_field(src, "data.win.system.ipAddress") or "-"

    return {
        "id":        hit.get("_id", ""),
        "timestamp": src.get("timestamp", ""),
        "rule":      rule.get("description", "Unknown rule"),
        "severity":  severity,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "agent":     agent.get("name", "unknown"),
        "status":    "open",
        "desc":      rule.get("description", ""),
        "log":       _raw_event(src)[:4000],
        "rule_id":   str(rule.get("id", "")),
        "groups":    rule.get("groups", []),
        "level":     level,
    }

def format_agent(a: dict) -> dict:
    return {
        "id":       a.get("id", ""),
        "name":     a.get("name", "unknown"),
        "ip":       a.get("ip", "unknown"),
        "status":   a.get("status", "unknown"),
        "os":       a.get("os", {}).get("name", "unknown"),
        "version":  a.get("version", "unknown"),
        "lastSeen": a.get("lastKeepAlive", ""),
    }

# ── Routes ────────────────────────────────────────────────────

@app.get("/health")
async def health():
    indexer = "unreachable"
    try:
        async with httpx.AsyncClient(**CLIENT_KWARGS) as client:
            r = await client.get(f"{INDEXER_HOST}/_cluster/health",
                                auth=(INDEXER_USER, INDEXER_PASS))
        if r.status_code == 200:
            indexer = r.json().get("status", "unknown")
        else:
            indexer = f"http {r.status_code}"
    except Exception:
        indexer = "unreachable"

    try:
        # Force a fresh authentication so this endpoint actually proves the
        # credentials work, rather than reporting a stale cached token as ok.
        await get_token(force_refresh=True)
        return {
            "backend":       "ok",
            "wazuh":         "ok",
            "indexer":       indexer,
            "authenticated": True,
            "email":         email_is_configured(),
            "timestamp":     datetime.now().isoformat(),
        }
    except Exception as e:
        return {"backend": "ok", "wazuh": "error", "indexer": indexer,
                "detail": str(e), "timestamp": datetime.now().isoformat()}


# ── Alert query builder ──────────────────────────────────────────────────
# The severity and search filters must be applied INSIDE the OpenSearch query,
# i.e. BEFORE the result set is sliced to `limit`. Filtering in Python after
# the slice produced false negatives (e.g. ?limit=3&severity=medium -> 0).
#
# Level ranges must stay in sync with format_opensearch_alert():
#     level >= 12 -> high     level >= 7 -> medium     else -> low
SEVERITY_RANGES = {
    "high":   {"gte": 12},
    "medium": {"gte": 7, "lt": 12},
    "low":    {"lt": 7},
}

# Fields the `search` parameter is matched against. These mirror what the
# formatted alert exposes: src_ip (data.srcip or agent.ip), the rule
# description and the agent name.
SEARCH_FIELDS = ("data.srcip", "agent.ip", "rule.description", "agent.name", "rule.id")


def build_alert_query(severity: str = None, search: str = None) -> dict:
    """Build an OpenSearch query applying severity/search filters up-front."""
    bool_query = {}

    if severity and severity != "all":
        rng = SEVERITY_RANGES.get(severity.lower())
        if rng:
            bool_query["must"] = [{"range": {"rule.level": rng}}]

    if search:
        term = search.strip()
        if term:
            # Escape the wildcard metacharacters so a user search for "*"
            # does not turn into a match-everything pattern.
            escaped = term.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
            pattern = f"*{escaped}*"
            bool_query["should"] = [
                {"wildcard": {f: {"value": pattern, "case_insensitive": True}}}
                for f in SEARCH_FIELDS
            ]
            bool_query["minimum_should_match"] = 1

    if not bool_query:
        return {"match_all": {}}
    return {"bool": bool_query}


@app.get("/api/alerts")
async def get_alerts(
    background_tasks: BackgroundTasks,
    limit: int = Query(500, le=1000),
    severity: str = Query(None),
    search: str = Query(None),
):
    # Query OpenSearch indexer directly (has ALL alerts).
    # Filters are applied inside the query so `total` reflects every alert
    # matching them, while `data` is the limited slice.
    query = build_alert_query(severity, search)
    async with httpx.AsyncClient(**CLIENT_KWARGS) as client:
        r = await client.post(
            f"{INDEXER_HOST}/{INDEXER_INDEX}/_search",
            auth=(INDEXER_USER, INDEXER_PASS),
            json={
                "size": limit,
                "track_total_hits": True,
                # Severity first, then newest first: the dashboard's alert table
                # must show the HIGH severity alerts at the top instead of
                # burying them under the low-severity noise.
                "sort": [
                    {"rule.level": {"order": "desc"}},
                    {"timestamp": {"order": "desc"}},
                ],
                "query": query,
            },
        )

    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    body = r.json()
    hits = body.get("hits", {}).get("hits", [])
    alerts = [format_opensearch_alert(h) for h in hits]

    # Send email for high severity
    check_and_alert(alerts, background_tasks)

    # `total` = number of alerts matching the filters, BEFORE the limit slice.
    # `data`  = the limited slice that was actually returned.
    total = body.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        total = total.get("value", len(alerts))
    else:
        total = len(alerts)

    return {"success": True, "total": total, "data": alerts}


@app.get("/api/stats")
async def get_stats():
    async with httpx.AsyncClient(**CLIENT_KWARGS) as client:
        r = await client.post(
            f"{INDEXER_HOST}/{INDEXER_INDEX}/_search",
            auth=(INDEXER_USER, INDEXER_PASS),
            json={
                "size": 0,
                "track_total_hits": True,
                "aggs": {
                    "high":   {"filter": {"range": {"rule.level": {"gte": 12}}}},
                    "medium": {"filter": {"range": {"rule.level": {"gte": 7, "lt": 12}}}},
                    "low":    {"filter": {"range": {"rule.level": {"lt": 7}}}},
                },
            },
        )

    data = r.json()
    total = data.get("hits", {}).get("total", {}).get("value", 0)
    aggs  = data.get("aggregations", {})

    return {
        "success": True,
        "total":   total,
        "high":    aggs.get("high",   {}).get("doc_count", 0),
        "medium":  aggs.get("medium", {}).get("doc_count", 0),
        "low":     aggs.get("low",    {}).get("doc_count", 0),
    }

@app.get("/api/agents")
async def get_agents():
    r = await wazuh_api_get("/agents", params={"limit": 500})
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    items = r.json().get("data", {}).get("affected_items", [])
    return {
        "success": True,
        "total":   len(items),
        "data":    [format_agent(a) for a in items],
    }


@app.post("/api/test-email")
async def test_email(background_tasks: BackgroundTasks):
    """Send a test email to verify email config is working."""
    test_alert = {
        "id":        "test-001",
        "rule":      "TEST — Email Alert System Working",
        "severity":  "high",
        "src_ip":    "192.168.1.176",
        "agent":     "test-agent",
        "timestamp": datetime.now().isoformat(),
        "desc":      "This is a test alert to confirm your email notifications are working correctly.",
        "log":       "Test log entry from SIEM Dashboard",
    }
    background_tasks.add_task(send_email_alert, test_alert)
    if not email_is_configured():
        return {"success": False,
                "message": "SMTP credentials are not configured. Set EMAIL_SENDER, "
                           "EMAIL_PASSWORD and EMAIL_RECEIVER in .env."}
    return {"success": True, "message": f"Test email sent to {EMAIL_RECEIVER}"}
