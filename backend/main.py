import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import router as auth_router, get_current_user
from app.models import Event, User
from app.database import get_db, init_db, engine
from app.schemas import UserOut, EventOut
from app.stats import router as stats_router
from app.siem import router as siem_router
from app.detection.request_logging import log_sql_injection_request
from app.detection.brute_force import run_all, persist_alerts
from app.detection.dos_detection import log_dos_request, run_dos_detection

from pathlib import Path

WEB_DIR = Path(__file__).resolve().parents[1] / "web"
DETECTION_INTERVAL_SECONDS = 60


async def run_detection_loop():
    while True:
        try:
            with Session(engine) as db:
                findings = run_all(db)
                persist_alerts(db, findings)
        except Exception as e:
            print(f"Detection loop error: {e}")
        await asyncio.sleep(DETECTION_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    brute_force_task = asyncio.create_task(run_detection_loop())
    dos_task = asyncio.create_task(run_dos_detection())
    try:
        yield
    finally:
        brute_force_task.cancel()
        dos_task.cancel()
        try:
            await brute_force_task
        except asyncio.CancelledError:
            pass
        try:
            await dos_task
        except asyncio.CancelledError:
            pass


app = FastAPI(lifespan=lifespan)
app.middleware("http")(log_sql_injection_request)

app.include_router(auth_router)


# Check whether the authenticated user is an admin
def require_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


app.include_router(stats_router, dependencies=[Depends(require_admin)])
app.include_router(siem_router, dependencies=[Depends(require_admin)])


@app.get("/")
def login_page():
    return FileResponse(WEB_DIR / "login.html")


@app.get("/register")
def register_page():
    return FileResponse(WEB_DIR / "register.html")


@app.get("/user")
def user_page():
    return FileResponse(WEB_DIR / "user.html")


@app.get("/admin")
def admin_page():
    return FileResponse(WEB_DIR / "admin.html")

@app.get("/dashboard")
def dashboard_page():
    return FileResponse(WEB_DIR / "dashboard.html")

@app.get("/api/admin/check")
def check_admin(admin: User = Depends(require_admin)):
    return {"admin": True}

@app.get("/api/admin/users", response_model=list[UserOut])
def list_users(
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return db.scalars(select(User).order_by(User.id).offset(offset).limit(limit)).all()


@app.get("/api/admin/events", response_model=list[EventOut])
def list_events(
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return db.scalars(select(Event).order_by(Event.event_id).offset(offset).limit(limit)).all()