import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

load_dotenv()

from app.database.database import init_db
from app.routes import devices, users, reports, audit, workstations, dashboard
from app.routes.employees import router as employees_router
from app.routes.workspaces import router as workspaces_router
from app.routes.devices import execute_background_scan
from app.routes.cve import router as cve_router
from app.routes.events import router as events_router
from app.routes.network_alerts import router as network_alerts_router
from app.database.database import get_db_connection
from app.scanner.snmp_scan import fetch_snmp_telemetry
from app.routes.workstations import process_telemetry_report, TelemetryReport
from app.scanner.network_sniffer import sniffer

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

def poll_agentless_telemetry():
    """Background job that queries SNMP for all active devices and ingests their telemetry."""
    print("[Agentless Polling] Starting background SNMP polling cycle...")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM devices WHERE status = 'active'")
        active_devices = [r["ip"] for r in cursor.fetchall()]

        for ip in active_devices:
            telemetry_data = fetch_snmp_telemetry(ip)
            if telemetry_data:
                print(f"[Agentless Polling] Fetched SNMP telemetry for {ip}")
                report = TelemetryReport(**telemetry_data)
                try:
                    process_telemetry_report(report, conn)
                except Exception as e:
                    print(f"[Agentless Polling] Failed to process telemetry for {ip}: {e}")
    except Exception as e:
        print(f"[Agentless Polling] Error in polling cycle: {e}")
    finally:
        conn.close()

# Initialize database tables and insert baseline demo data if they do not exist
init_db()

scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start the scheduler
    scheduler.add_job(execute_background_scan, 'interval', minutes=15)
    scheduler.add_job(poll_agentless_telemetry, 'interval', seconds=60)
    scheduler.start()

    # Start the network sniffer
    sniffer.start()

    yield
    # Shutdown the scheduler and sniffer
    scheduler.shutdown()
    sniffer.stop()

app = FastAPI(
    lifespan=lifespan,
    title="Recon NDS - Network Device Scanner API",
    description="A FastAPI backend for Recon NDS (Network Device Scanner), detecting active devices and logging scan reports.",
    version="2.1.0"
)

# ── Rate Limiting ─────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS Policy ───────────────────────────────────────────────────────────────
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000")
allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Agent-Key"],
)

# ── Security Headers Middleware ───────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response

# Mount the static directory to serve CSS and JS
app.mount("/static", StaticFiles(directory="static"), name="static")

from fastapi.responses import FileResponse

# Root endpoint: Serve the SPA frontend
@app.get("/")
async def serve_spa():
    return FileResponse("static/index.html")

# Core API routers
app.include_router(devices.router, prefix="/api/devices", tags=["Devices"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(audit.router, prefix="/api/audit", tags=["Audit"])
app.include_router(workstations.router, prefix="/api/workstations", tags=["Workstations"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])

# Feature routers
app.include_router(employees_router, prefix="/api/employees", tags=["Employees"])
app.include_router(workspaces_router, prefix="/api/workspaces", tags=["Workspaces"])
app.include_router(cve_router, prefix="/api/cve", tags=["CVE"])
app.include_router(events_router, prefix="/api/events", tags=["Events"])
app.include_router(network_alerts_router, prefix="/api/network-alerts", tags=["Network Alerts"])
