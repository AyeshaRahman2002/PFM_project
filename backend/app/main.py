# app/main.py
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import date, datetime, timedelta
from typing import List, Tuple, Optional, Dict, Any
from collections import defaultdict, Counter
import os, uuid, shutil, hashlib, math, json, hmac
import ipaddress
from functools import lru_cache
import secrets
import re

from .database import Base, engine, get_db
from . import models, schemas, auth
from .deps import current_user
from app.pydantic_compat import model_to_dict
from . import risk_engine, anomaly_engine
from .anomaly_engine import AnomalyDetector, DetectorConfig, IFConfig, AEConfig
from app.routers import logs as logs_router
from app.routers import recs as recs_router
from app.routers import fed as fed_router
from app.routers import fed_sim as fed_sim_router
from app.routers.xai_shap import router as xai_router
from app.routers import adversary as adversary_router
from app.routers import ti as ti_router
from app import threat_intel
from app.routers import soc

app = FastAPI(title="PFM MVP API", version="0.5.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(logs_router.router)
app.include_router(recs_router.router)
app.include_router(fed_router.router)
app.include_router(fed_sim_router.router)
app.include_router(xai_router)
app.include_router(adversary_router.router)
app.include_router(ti_router.router)
app.include_router(soc.router)

# Static media (for avatars)
os.makedirs("static/avatars", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Ensure tables exist (after models import)
Base.metadata.create_all(bind=engine)

# Warm-load TI feeds (safe even if files are missing or TI disabled)
try:
    threat_intel.reload()
except Exception:
    pass

# Config (geolocation/proxy)
GEO_PROVIDER = os.getenv("GEO_PROVIDER", "MAXMIND").upper()  # MAXMIND or IPINFO
GEOIP_DB = os.getenv("GEOIP_DB", "./data/GeoLite2-City.mmdb")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", None)
TRUSTED_PROXIES = [c.strip() for c in os.getenv("TRUSTED_PROXIES", "").split(",") if c.strip()]  # CIDRs

# Helpers (security)
DEVICE_FINGERPRINT_SECRET = os.getenv("DEVICE_FINGERPRINT_SECRET", "dev-fingerprint-secret-change-me")
DEVICE_HASH_LEN = int(os.getenv("DEVICE_HASH_LEN", "64"))

def _hash_device(seed: str) -> str:
    digest = hmac.new(
        DEVICE_FINGERPRINT_SECRET.encode("utf-8"),
        seed.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:DEVICE_HASH_LEN]

def _hash_device_legacy_sha1(seed: str) -> str:
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

_TRUSTED_PROXY_HEADERS = ("x-forwarded-for", "x-real-ip", "cf-connecting-ip")

def _ip_in_trusted(peer_ip: str) -> bool:
    if not TRUSTED_PROXIES:
        return False
    try:
        peer = ipaddress.ip_address(peer_ip)
    except Exception:
        return False
    for cidr in TRUSTED_PROXIES:
        try:
            if peer in ipaddress.ip_network(cidr, strict=False):
                return True
        except Exception:
            continue
    return False

def _client_ip(req: Request) -> str:
    peer = req.client.host if req.client else "0.0.0.0"
    if _ip_in_trusted(peer):
        for h in _TRUSTED_PROXY_HEADERS:
            v = req.headers.get(h)
            if not v:
                continue
            ip = v.split(",")[0].strip()
            try:
                ipaddress.ip_address(ip)
                return ip
            except Exception:
                continue
    return peer

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

@lru_cache(maxsize=5000)
def _geo_maxmind(ip: str) -> Tuple[float, float, str]:
    try:
        from geoip2.database import Reader
        if not hasattr(_geo_maxmind, "_reader"):
            _geo_maxmind._reader = Reader(GEOIP_DB)
        r = _geo_maxmind._reader.city(ip)
        city = (r.city.name or "") or "Unknown"
        cc = r.country.iso_code or ""
        name = f"{city}, {cc}".strip().strip(",")
        lat = float(r.location.latitude or 0.0)
        lon = float(r.location.longitude or 0.0)
        return (lat, lon, name or "Unknown")
    except Exception:
        return (0.0, 0.0, "Unknown")

@lru_cache(maxsize=5000)
def _geo_ipinfo(ip: str) -> Tuple[float, float, str]:
    try:
        import httpx
        url = f"https://ipinfo.io/{ip}"
        params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}
        with httpx.Client(timeout=2.5) as c:
            r = c.get(url, params=params)
            r.raise_for_status()
            j = r.json()
            lat, lon = 0.0, 0.0
            if isinstance(j.get("loc"), str) and "," in j["loc"]:
                lat_s, lon_s = j["loc"].split(",", 1)
                lat, lon = float(lat_s), float(lon_s)
            city = j.get("city") or "Unknown"
            country = j.get("country") or ""
            name = f"{city}, {country}".strip().strip(",")
            return (lat, lon, name or "Unknown")
    except Exception:
        return (0.0, 0.0, "Unknown")

def _geo_for_ip(ip: str) -> Tuple[float, float, str]:
    if _is_private(ip) or ip.startswith("127."):
        return (0.0, 0.0, "Unknown")
    if GEO_PROVIDER == "IPINFO":
        return _geo_ipinfo(ip)
    return _geo_maxmind(ip)

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2.0)**2 + math.cos(p1)*math.cos(p2)*math.sin(dlambda/2.0)**2
    return 2 * R * math.asin(math.sqrt(a))

# Thresholds (kept in sync with risk_engine)
LOCK_WINDOW_MIN = 15
MAX_FAILS = 5
RISK_STEP_UP_THRESHOLD = int(os.getenv("RISK_STEP_UP_THRESHOLD", "60"))
RISK_HARD_DENY = int(os.getenv("RISK_HARD_DENY", "90"))
risk_engine.CONFIG.step_up_threshold = RISK_STEP_UP_THRESHOLD
risk_engine.CONFIG.hard_deny_threshold = RISK_HARD_DENY

def _decay_score(value: int, since: Optional[datetime], half_life_days: int = 30) -> int:
    if not since:
        return value
    days = max((datetime.utcnow() - since).days, 0)
    factor = 0.5 ** (days / float(half_life_days))
    return int(round(value * factor))

# Auth
@app.post("/auth/register", response_model=schemas.UserOut)
def register(body: schemas.UserCreate, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == body.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    user = models.User(email=body.email, password_hash=auth.hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post("/auth/login", response_model=schemas.Token)
def login(body: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == body.email).first()
    ip = _client_ip(request)
    ua = request.headers.get("User-Agent", "")

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.lock_until and datetime.utcnow() < user.lock_until:
        raise HTTPException(status_code=423, detail="Account temporarily locked. Try again later.")

    seed = (body.device.device_id if body.device and body.device.device_id else "") + ua
    if body.device:
        seed += (body.device.os or "") + (body.device.model or "") + (body.device.locale or "")
    device_hash = _hash_device(seed) if seed else None
    legacy_hash = _hash_device_legacy_sha1(seed) if seed else None

    known_device = None
    if device_hash:
        known_device = (
            db.query(models.DeviceFingerprint)
            .filter(
                models.DeviceFingerprint.user_id == user.id,
                models.DeviceFingerprint.device_hash.in_([device_hash, legacy_hash]),
            ).first()
        )

    binding_token = request.headers.get("x-device-binding") or (body.device_binding if hasattr(body, "device_binding") else None)
    bound_device = None
    if binding_token:
        try:
            b_hash = _sha256_hex(binding_token)
            bound_device = (
                db.query(models.DeviceFingerprint)
                .filter(
                    models.DeviceFingerprint.user_id == user.id,
                    models.DeviceFingerprint.bind_token_hash == b_hash,
                ).first()
            )
            if bound_device:
                bound_device.bind_last_used = datetime.utcnow()
                db.add(bound_device)
                device_hash = bound_device.device_hash
                known_device = bound_device
        except Exception:
            bound_device = None

    ok = auth.verify_password(body.password, user.password_hash)
    if not ok:
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= MAX_FAILS:
            user.lock_until = datetime.utcnow() + timedelta(minutes=LOCK_WINDOW_MIN)
        db.add(user)
        db.add(models.LoginEvent(
            user_id=user.id, ip=ip, user_agent=ua, device_hash=device_hash,
            success=False, risk_score=0, risk_reason="bad_password"
        ))
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    consecutive_fails = user.failed_attempts or 0
    user.failed_attempts = 0
    user.lock_until = None

    if known_device and len(known_device.device_hash or "") == 40 and device_hash:
        known_device.device_hash = device_hash
        db.add(known_device)

    if bound_device and not bound_device.trusted:
        bound_device.trusted = True
        db.add(bound_device)
        intel_for_trust = _get_or_create_intel(db, user.id)
        devtrust = dict(intel_for_trust.device_trust or {})
        devtrust[bound_device.device_hash] = True
        intel_for_trust.device_trust = devtrust
        db.add(intel_for_trust)

    # AI-Driven Risk Scoring (via risk_engine)
    is_new_device = device_hash is not None and known_device is None
    ip_changed = bool(known_device and known_device.last_ip and known_device.last_ip != ip)

    # fetch intel + recent events (ASC)
    intel = _get_or_create_intel(db, user.id)
    recent = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == user.id)
        .order_by(models.LoginEvent.ts.asc())
        .all()
    )
    now = datetime.utcnow()
    candidate = recent + [models.LoginEvent(
        user_id=user.id, ip=ip, user_agent=ua, device_hash=device_hash,
        success=True, ts=now
    )]

    # computing speed for “impossible travel”
    def _last_two_success(evts: List[models.LoginEvent]):
        ss = [r for r in evts if r.success]
        return ss[-2:] if len(ss) >= 2 else ss

    last2 = _last_two_success(candidate)
    speed_kmh = None
    if len(last2) == 2:
        a, b = last2[0], last2[1]
        lat1, lon1, _ = _geo_for_ip(a.ip or "127.0.0.1")
        lat2, lon2, _ = _geo_for_ip(b.ip or "127.0.0.1")
        dist_km = _haversine_km(lat1, lon1, lat2, lon2)
        dt_hours = max((b.ts - a.ts).total_seconds() / 3600.0, 0.05)
        speed_kmh = dist_km / dt_hours

    _, _, ip_city = _geo_for_ip(ip or "127.0.0.1")
    prior_success = next((r for r in reversed(recent) if r.success), None)
    known_first_seen = getattr(known_device, "first_seen", None) if known_device else None

    # Threat Intelligence lookups (lightweight, cached)
    ti_ip = threat_intel.lookup_ip(ip or "0.0.0.0")
    ti_email = threat_intel.check_email_domain(user.email or "")
    ti_breach = threat_intel.check_breached_cred(user.email or "")

    ti_labels = []
    ti_labels.extend(ti_ip.get("ti_labels", []) or [])
    if ti_email.get("ti_disposable_email"):
        ti_labels.append(f"disp_email:{ti_email.get('domain')}")
    if ti_breach.get("ti_breached_cred"):
        ti_labels.append("breached_cred")

    # Call risk_engine without TI kwargs (to avoid TypeError)
    base_score, parts, _details = risk_engine.score_login(
        cfg=risk_engine.CONFIG,
        recent_rows=candidate,
        login_cities=dict(intel.login_cities or {}),
        login_hours_hist=dict(intel.login_hours_hist or {}),
        device_trust=dict(intel.device_trust or {}),
        ip_city=ip_city,
        is_private_ip=_is_private(ip or "127.0.0.1"),
        device_hash=device_hash,
        known_device=not (is_new_device),
        ip_changed=ip_changed,
        consecutive_fails=consecutive_fails,
        now=now,
        last_success_ts=getattr(prior_success, "ts", None) if prior_success else None,
        speed_kmh=speed_kmh,
        known_device_first_seen=known_first_seen,
    )

    # Applying TI bumps post-score (safe; no engine signature change)
    extra = int(ti_ip.get("ti_score_bump_suggest", 0))
    if ti_email.get("ti_disposable_email"):
        extra += threat_intel.TI_DEFAULT_SCORE_BUMPS["ti_disposable_email"]
        parts.append(f"ti_disposable_email +{threat_intel.TI_DEFAULT_SCORE_BUMPS['ti_disposable_email']}")
    if ti_breach.get("ti_breached_cred"):
        extra += threat_intel.TI_DEFAULT_SCORE_BUMPS["ti_breached_cred"]
        parts.append(f"ti_breached_cred +{threat_intel.TI_DEFAULT_SCORE_BUMPS['ti_breached_cred']}")

    # annotate ip-based labels (bad_ip / tor / bad_asn)
    if ti_ip.get("ti_bad_ip"):
        parts.append(f"ti_bad_ip +{threat_intel.TI_DEFAULT_SCORE_BUMPS['ti_bad_ip']}")
    if ti_ip.get("ti_tor_exit"):
        parts.append(f"ti_tor_exit +{threat_intel.TI_DEFAULT_SCORE_BUMPS['ti_tor_exit']}")
    if ti_ip.get("ti_bad_asn"):
        parts.append(f"ti_bad_asn +{threat_intel.TI_DEFAULT_SCORE_BUMPS['ti_bad_asn']}")

    total_score = min(100, int(base_score) + int(extra))

    had_success = any(r.success for r in recent)
    if total_score >= RISK_HARD_DENY and had_success:
        db.add(models.LoginEvent(
            user_id=user.id, ip=ip, user_agent=ua, device_hash=device_hash,
            success=False, risk_score=total_score,
            risk_reason="hard_deny|" + "|".join(parts)
        ))
        db.commit()
        raise HTTPException(status_code=403, detail="Login blocked for security")

    step_up = total_score >= RISK_STEP_UP_THRESHOLD

    if device_hash:
        if not known_device:
            label = (body.device.model or body.device.os) if body.device else None
            known_device = models.DeviceFingerprint(
                user_id=user.id,
                device_hash=device_hash,
                label=label,
                trusted=False if not bound_device else True,
                first_seen=now,
                last_seen=now,
                last_ip=ip,
                user_agent=ua,
            )
            db.add(known_device)
        else:
            known_device.last_seen = now
            known_device.last_ip = ip
            known_device.user_agent = ua
            db.add(known_device)

    db.add(models.LoginEvent(
        user_id=user.id, ip=ip, user_agent=ua, device_hash=device_hash,
        success=True, risk_score=total_score, risk_reason="|".join(parts)
    ))
    db.add(user)
    db.commit()

    _learn_login(db, user, ip, device_hash, now)

    token = auth.create_access_token(user.email)
    return schemas.Token(
        access_token=token,
        risk_score=total_score,
        step_up_required=step_up,
        message="step-up suggested" if step_up else "ok",
    )

@app.get("/me", response_model=schemas.UserOut)
def me(u: models.User = Depends(current_user)):
    return u

# Security Center
@app.get("/security/devices", response_model=List[schemas.DeviceOut])
def list_devices(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    rows = (
        db.query(models.DeviceFingerprint)
        .filter(models.DeviceFingerprint.user_id == u.id)
        .order_by(models.DeviceFingerprint.last_seen.desc())
        .all()
    )
    return [
        schemas.DeviceOut(
            device_hash=r.device_hash,
            label=r.label,
            trusted=r.trusted,
            first_seen=r.first_seen,
            last_seen=r.last_seen,
            last_ip=r.last_ip,
            user_agent=r.user_agent,
        )
        for r in rows
    ]

@app.post("/security/devices/{device_hash}/trust", response_model=dict)
def trust_device(device_hash: str, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    d = (
        db.query(models.DeviceFingerprint)
        .filter(
            models.DeviceFingerprint.user_id == u.id,
            models.DeviceFingerprint.device_hash == device_hash,
        ).first()
    )
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    d.trusted = True
    db.add(d)
    db.commit()
    return {"ok": True}

@app.get("/security/logins", response_model=List[schemas.LoginEventOut])
def login_history(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    rows = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id)
        .order_by(models.LoginEvent.ts.desc())
        .limit(50)
        .all()
    )
    return [
        schemas.LoginEventOut(
            ts=r.ts,
            ip=r.ip,
            user_agent=r.user_agent,
            device_hash=r.device_hash,
            success=r.success,
            risk_score=r.risk_score,
            risk_reason=r.risk_reason,
        )
        for r in rows
    ]

@app.get("/security/sessions", response_model=List[schemas.SessionOut])
def list_sessions(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    rows = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id, models.LoginEvent.success == True)  # noqa: E712
        .order_by(models.LoginEvent.ts.desc())
        .limit(10)
        .all()
    )
    out: List[schemas.SessionOut] = []
    for r in rows:
        out.append(
            schemas.SessionOut(
                session_id=str(r.id),
                created_at=r.ts,
                last_seen=r.ts,
                device_hash=r.device_hash,
                ip=r.ip,
                revoked=False,
            )
        )
    return out

# Impossible travel quick check (last 2 successes)
@app.get("/security/impossible_travel", response_model=dict)
def impossible_travel_check(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    rows = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id, models.LoginEvent.success == True)  # noqa: E712
        .order_by(models.LoginEvent.ts.desc())
        .limit(2)
        .all()
    )
    if len(rows) < 2:
        return {"enough_data": False}

    a, b = rows[1], rows[0]
    lat1, lon1, city1 = _geo_for_ip(a.ip or "127.0.0.1")
    lat2, lon2, city2 = _geo_for_ip(b.ip or "127.0.0.1")
    dist_km = _haversine_km(lat1, lon1, lat2, lon2)
    dt_hours = max((b.ts - a.ts).total_seconds() / 3600.0, 0.05)
    speed = dist_km / dt_hours
    flagged = speed > 750.0
    return {
        "enough_data": True,
        "from": {"ip": a.ip, "city": city1},
        "to": {"ip": b.ip, "city": city2},
        "distance_km": round(dist_km, 1),
        "hours_between": round(dt_hours, 2),
        "speed_kmh": round(speed, 1),
        "flagged": flagged,
    }

# Security analytics: daily login metrics (last 30 days)
@app.get("/security/metrics", response_model=dict)
def security_metrics(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    today = datetime.utcnow().date()
    start_dt = datetime(today.year, today.month, today.day) - timedelta(days=29)

    rows = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id, models.LoginEvent.ts >= start_dt)
        .order_by(models.LoginEvent.ts.asc())
        .all()
    )

    daily = defaultdict(lambda: {"success": 0, "fail": 0, "risky": 0})
    totals = {"success": 0, "fail": 0, "risky": 0}

    for r in rows:
        d = r.ts.date().isoformat()
        if r.success:
            daily[d]["success"] += 1
            totals["success"] += 1
            if (r.risk_score or 0) >= RISK_STEP_UP_THRESHOLD:
                daily[d]["risky"] += 1
                totals["risky"] += 1
        else:
            daily[d]["fail"] += 1
            totals["fail"] += 1

    series = []
    for i in range(30):
        day = (start_dt.date() + timedelta(days=i)).isoformat()
        series.append({"date": day, **daily[day]})

    trusted = (
        db.query(models.DeviceFingerprint)
        .filter(models.DeviceFingerprint.user_id == u.id, models.DeviceFingerprint.trusted == True)  # noqa: E712
        .count()
    )
    device_count = (
        db.query(models.DeviceFingerprint)
        .filter(models.DeviceFingerprint.user_id == u.id)
        .count()
    )

    return {"series": series, "totals": totals, "devices": {"trusted": trusted, "total": device_count}}

# Security analytics: recent login geos
@app.get("/security/geo_logins", response_model=dict)
def security_geo_logins(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    rows = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id, models.LoginEvent.success == True)  # noqa: E712
        .order_by(models.LoginEvent.ts.desc())
        .limit(20)
        .all()
    )
    out = []
    for r in rows:
        lat, lon, city = _geo_for_ip(r.ip or "127.0.0.1")
        out.append({
            "ts": r.ts.isoformat(),
            "ip": r.ip,
            "city": city,
            "lat": lat,
            "lon": lon,
            "risk": r.risk_score,
            "device": r.device_hash,
        })
    return {"logins": out}

# Transactions
@app.post("/transactions", response_model=schemas.TxOut)
def add_tx(body: schemas.TxCreate, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    tx = models.Transaction(
        user_id=u.id,
        amount=body.amount,
        currency=body.currency,
        category=body.category,
        date=body.date,
        merchant=body.merchant,
        notes=body.notes,
    )
    db.add(tx)
    db.commit()
    db.refresh(tx)
    _learn_tx(db, u, float(tx.amount), (tx.category or "").upper(), (tx.merchant or None))
    return tx

@app.get("/transactions", response_model=List[schemas.TxOut])
def list_txs(month: str, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    try:
        y, m = [int(x) for x in month.split("-")]
        start = date(y, m, 1)
        end = date(y + 1, 1, 1) if m == 12 else date(y, m + 1, 1)
    except Exception:
        raise HTTPException(status_code=400, detail="month must be YYYY-MM")

    q = (
        db.query(models.Transaction)
        .filter(
            models.Transaction.user_id == u.id,
            models.Transaction.date >= start,
            models.Transaction.date < end,
        )
        .order_by(models.Transaction.date.desc())
    )
    return q.all()

# Shared loader for ML
def _load_tx_rows_for_ml(db: Session, u: models.User, drop_newest: bool = False) -> List[Dict[str, Any]]:
    rows = (
        db.query(models.Transaction)
        .filter(models.Transaction.user_id == u.id)
        .order_by(models.Transaction.created_at.asc())
        .limit(500)
        .all()
    )
    if not rows:
        return []
    use = rows[:-1] if drop_newest and len(rows) >= 2 else rows
    out: List[Dict[str, Any]] = []
    for t in use:
        out.append({
            "amount": float(t.amount),
            "currency": t.currency,
            "category": (t.category or "").upper(),
            "date": t.date.isoformat() if t.date else None,
            "merchant": (t.merchant or None),
        })
    return out

# Transaction anomaly score (IForest + optional Autoencoder)
@app.get("/transactions/anomaly_score", response_model=dict)
def tx_anomaly_score(
    method: Optional[str] = None,  # "iforest" | "autoenc" | "ae" | "auto"
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    """
    Train on user history (all but most recent), score the newest transaction.
    """
    rows_all = _load_tx_rows_for_ml(db, u, drop_newest=False)
    if len(rows_all) < 2:
        return {"enough_data": False, "score": 0, "reason": "not_enough_data"}

    hist = rows_all[:-1]
    newest_row = rows_all[-1]

    # normalize method alias
    m = (method or "auto").lower()
    force = "autoenc" if m == "ae" else m

    detector = AnomalyDetector(DetectorConfig(method=force))
    used, score, details, n_train = detector.train_and_score(hist, newest_row, force_method=force)

    return {
        "enough_data": n_train > 0,
        "score": int(score),
        "method": used,
        "details": details,
        "n_train": n_train,
    }

# Shadow-mode rules evaluation
@app.post("/rules/test", response_model=dict)
def rules_test(payload: dict, u: models.User = Depends(current_user)):
    triggered: List[str] = []
    amt = float(payload.get("amount", 0) or 0)
    currency = (payload.get("currency") or "").upper()
    merchant = (payload.get("merchant") or "").lower()

    if amt >= 1000:
        triggered.append("HIGH_AMOUNT>=1000")
    if currency not in ("SAR", "USD", "EUR", "GBP", "AED") and amt > 0:
        triggered.append("UNCOMMON_CURRENCY")
    if "crypto" in merchant or "binance" in merchant or "coinbase" in merchant:
        triggered.append("CRYPTO_MERCHANT")

    return {"shadow_mode": True, "triggered": triggered}

# Budgets
@app.post("/budgets", response_model=schemas.BudgetOut)
def upsert_budget(body: schemas.BudgetCreate, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    b = (
        db.query(models.Budget)
        .filter(
            models.Budget.user_id == u.id,
            models.Budget.category == body.category,
            models.Budget.month == body.month,
            models.Budget.year == body.year,
        )
        .first()
    )
    if b:
        b.amount = body.amount
    else:
        b = models.Budget(user_id=u.id, **model_to_dict(body))
        db.add(b)
    db.commit()
    db.refresh(b)
    return b

@app.get("/budgets", response_model=List[schemas.BudgetOut])
def list_budgets(month: str, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    y, m = [int(x) for x in month.split("-")]
    return (
        db.query(models.Budget)
        .filter(
            models.Budget.user_id == u.id,
            models.Budget.month == m,
            models.Budget.year == y,
        )
        .all()
    )

# Goals
@app.post("/goals", response_model=schemas.GoalOut)
def create_goal(body: schemas.GoalCreate, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    g = models.Goal(user_id=u.id, **model_to_dict(body), current_amount=0)
    db.add(g)
    db.commit()
    db.refresh(g)
    return g

@app.get("/goals", response_model=List[schemas.GoalOut])
def list_goals(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    return (
        db.query(models.Goal)
        .filter(models.Goal.user_id == u.id)
        .order_by(models.Goal.created_at.desc())
        .all()
    )

@app.post("/goals/{goal_id}/contribute", response_model=schemas.GoalOut)
def contribute(goal_id: int, body: schemas.GoalContribute, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    g = (
        db.query(models.Goal)
        .filter(models.Goal.id == goal_id, models.Goal.user_id == u.id)
        .first()
    )
    if not g:
        raise HTTPException(status_code=404, detail="Goal not found")
    g.current_amount = (g.current_amount or 0) + body.amount
    db.commit()
    db.refresh(g)
    return g

# Insights
@app.get("/insights/summary", response_model=schemas.SummaryOut)
def summary(month: str, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    y, m = [int(x) for x in month.split("-")]
    start = date(y, m, 1)
    end = date(y + 1, 1, 1) if m == 12 else date(y, m + 1, 1)

    total = (
        db.query(func.coalesce(func.sum(models.Transaction.amount), 0))
        .filter(
            models.Transaction.user_id == u.id,
            models.Transaction.date >= start,
            models.Transaction.date < end,
        )
        .scalar()
        or 0
    )

    rows = (
        db.query(
            models.Transaction.category,
            func.sum(models.Transaction.amount).label("amt"),
        )
        .filter(
            models.Transaction.user_id == u.id,
            models.Transaction.date >= start,
            models.Transaction.date < end,
        )
        .group_by(models.Transaction.category)
        .order_by(func.sum(models.Transaction.amount).desc())
        .limit(3)
        .all()
    )

    top = [(r[0], float(r[1])) for r in rows]
    return {"total_spent": float(total), "top_categories": top}

# Profile
@app.get("/profile", response_model=schemas.ProfileOut)
def get_profile(u: models.User = Depends(current_user)):
    return {
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "dob": u.dob,
        "nationality": u.nationality,
        "avatar_url": u.avatar_url,
    }

@app.put("/profile", response_model=schemas.ProfileOut)
def update_profile(body: schemas.ProfileIn, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    if body.first_name is not None:
        u.first_name = body.first_name
    if body.last_name is not None:
        u.last_name = body.last_name
    if body.dob is not None:
        u.dob = body.dob
    if body.nationality is not None:
        u.nationality = body.nationality
    if body.avatar_url is not None:
        u.avatar_url = body.avatar_url
    db.add(u)
    db.commit()
    db.refresh(u)
    return {
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "dob": u.dob,
        "nationality": u.nationality,
        "avatar_url": u.avatar_url,
    }

# Avatar upload
@app.post("/me/avatar", response_model=schemas.UserOut)
def upload_avatar_me(file: UploadFile = File(...), db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        raise HTTPException(status_code=400, detail="Unsupported image type")

    fname = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join("static/avatars", fname)
    with open(path, "wb") as out:
        shutil.copyfileobj(file.file, out)

    u.avatar_url = f"/static/avatars/{fname}"
    db.add(u)
    db.commit()
    db.refresh(u)
    return u

@app.post("/profile/avatar", response_model=schemas.UserOut)
def upload_avatar_alias(file: UploadFile = File(...), db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    return upload_avatar_me(file=file, db=db, u=u)

# Account Deletion
@app.delete("/me", status_code=204)
def delete_me(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    if u.avatar_url and u.avatar_url.startswith("/static/avatars/"):
        try:
            avatar_path = u.avatar_url.lstrip("/")
            if os.path.exists(avatar_path):
                os.remove(avatar_path)
        except Exception:
            pass

    db.delete(u)
    db.commit()
    return Response(status_code=204)

# Audit export (NDJSON)
@app.get("/export/audit", response_model=None)
def export_audit(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    lines: List[str] = []

    logins = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id)
        .order_by(models.LoginEvent.ts.desc())
        .limit(200)
        .all()
    )
    for r in logins:
        lines.append(json.dumps({
            "type": "login",
            "ts": r.ts.isoformat(),
            "ip": r.ip,
            "ua": r.user_agent,
            "device": r.device_hash,
            "success": r.success,
            "risk": r.risk_score,
            "reason": r.risk_reason,
        }))

    txs = (
        db.query(models.Transaction)
        .filter(models.Transaction.user_id == u.id)
        .order_by(models.Transaction.created_at.desc())
        .limit(500)
        .all()
    )
    for t in txs:
        lines.append(json.dumps({
            "type": "transaction",
            "ts": (t.created_at or datetime.utcnow()).isoformat(),
            "amount": float(t.amount),
            "currency": t.currency,
            "category": t.category,
            "merchant": t.merchant,
            "notes": t.notes,
        }))

    body = "\n".join(lines) + "\n"
    return Response(content=body, media_type="application/x-ndjson")

# Intelligence helpers
def _get_or_create_intel(db: Session, user_id: int) -> models.UserIntel:
    intel = db.query(models.UserIntel).filter(models.UserIntel.user_id == user_id).first()
    if not intel:
        intel = models.UserIntel(
            user_id=user_id,
            login_hours_hist={str(h): 0 for h in range(24)},
            login_cities={},
            device_trust={},
            tx_category_stats={},
            tx_merchant_counts={},
        )
        db.add(intel); db.commit(); db.refresh(intel)
    return intel

def _median(xs: List[float]) -> float:
    if not xs: return 0.0
    s = sorted(xs); n = len(s); m = n//2
    return float(s[m] if n % 2 else (s[m-1]+s[m])/2)

def _mad(xs: List[float], med: Optional[float] = None) -> float:
    if not xs: return 0.0
    med = med if med is not None else _median(xs)
    devs = [abs(x - med) for x in xs]
    return 1.4826 * _median(devs)

def _learn_login(db: Session, u: models.User, ip: str, device_hash: Optional[str], when: datetime):
    intel = _get_or_create_intel(db, u.id)
    h = str(when.hour)
    hist = dict(intel.login_hours_hist or {})
    hist[h] = int(hist.get(h, 0)) + 1
    intel.login_hours_hist = hist

    _, _, city = _geo_for_ip(ip or "127.0.0.1")
    cities = dict(intel.login_cities or {})
    cities[city] = int(cities.get(city, 0)) + 1
    intel.login_cities = cities

    devtrust = dict(intel.device_trust or {})
    if device_hash:
        d = (db.query(models.DeviceFingerprint)
                .filter(models.DeviceFingerprint.user_id==u.id,
                        models.DeviceFingerprint.device_hash==device_hash).first())
        if d: devtrust[device_hash] = bool(d.trusted)
    intel.device_trust = devtrust
    db.add(intel); db.commit()

def _learn_tx(db: Session, u: models.User, amount: float, category: str, merchant: Optional[str]):
    intel = _get_or_create_intel(db, u.id)
    stats = dict(intel.tx_category_stats or {})
    s = dict(stats.get(category, {"n":0,"median":0.0,"mad":0.0}))
    n = int(s.get("n", 0))
    alpha = 0.1
    if n == 0:
        s["median"] = float(amount)
        s["mad"] = 0.0
    else:
        s["median"] = (1-alpha)*float(s["median"]) + alpha*float(amount)
        s["mad"] = (1-alpha)*float(s["mad"]) + alpha*abs(float(amount) - float(s["median"]))
    s["n"] = n + 1
    stats[category] = s
    intel.tx_category_stats = stats

    mcounts = dict(intel.tx_merchant_counts or {})
    if merchant:
        key = (merchant or "").lower()
        mcounts[key] = int(mcounts.get(key, 0)) + 1
    intel.tx_merchant_counts = mcounts

    db.add(intel); db.commit()

def _score_tx(intel: models.UserIntel, payload: Dict[str, Any]) -> Tuple[int, List[str], Dict[str, Any]]:
    amt = float(payload.get("amount") or 0)
    cat = (payload.get("category") or "").upper()
    merch = (payload.get("merchant") or "").lower()

    parts = []
    details = {}

    s = (intel.tx_category_stats or {}).get(cat, {"n":0,"median":0.0,"mad":0.0})
    med, mad, n = float(s.get("median", 0)), float(s.get("mad", 0)), int(s.get("n", 0))
    z = 0.0 if mad <= 1e-6 else abs(amt - med) / mad
    details.update({"median": med, "mad": mad, "n": n, "z": round(z,2)})

    score = 0
    if n >= 5:
        bump = min(int(z * 12), 70)
        score += bump
        parts.append(f"amount_deviation(z≈{z:.1f}) +{bump}")

    seen_merch = int((intel.tx_merchant_counts or {}).get(merch, 0))
    if merch and seen_merch == 0 and amt >= 100:
        score += 20; parts.append("new_merchant +20")
    elif merch and seen_merch <= 2 and amt >= 250:
        score += 10; parts.append("rare_merchant +10")

    cur = (payload.get("currency") or "").upper()
    if cur not in ("SAR","USD","EUR","GBP","AED") and amt > 0:
        score += 10; parts.append("uncommon_currency +10")

    return min(score, 100), parts, details

# Intelligence: view learned profile
@app.get("/intelligence/profile", response_model=schemas.IntelProfileOut)
def intel_profile(db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    intel = _get_or_create_intel(db, u.id)
    return {
        "login_hours_hist": intel.login_hours_hist or {},
        "login_cities": intel.login_cities or {},
        "device_trust": intel.device_trust or {},
        "tx_category_stats": intel.tx_category_stats or {},
        "tx_merchant_counts": intel.tx_merchant_counts or {},
    }

# score a hypothetical transaction
@app.post("/intelligence/score/tx", response_model=schemas.ScoreBreakdown)
def score_tx(payload: schemas.TxScoreIn, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    intel = _get_or_create_intel(db, u.id)
    total, parts, details = _score_tx(intel, model_to_dict(payload))  # <-- compat
    return {"total": total, "parts": parts, "details": details}

# score the most recent login (or provided one)
@app.post("/intelligence/score/login", response_model=schemas.ScoreBreakdown)
def score_login(body: Optional[schemas.LoginScoreIn] = None, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    intel = _get_or_create_intel(db, u.id)
    rows = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id)
        .order_by(models.LoginEvent.ts.asc())
        .all()
    )
    if not rows:
        return {"total": 0, "parts": ["no_history"], "details": {}}

    if body and (body.ip or body.device_hash):
        from copy import deepcopy
        e = deepcopy(rows[-1])
        if body.ip: e.ip = body.ip
        if body.device_hash: e.device_hash = body.device_hash
        e.ts = datetime.utcnow()
        candidate = rows + [e]
    else:
        candidate = rows

    # Mirror runtime scoring (risk_engine), not the legacy heuristic
    last_success = next((r for r in reversed(candidate) if r.success), None)
    cur_ip = (candidate[-1].ip if candidate else "127.0.0.1") or "127.0.0.1"
    _, _, ip_city = _geo_for_ip(cur_ip)

    def _last_two_success(evts):
        ss = [r for r in evts if r.success]
        return ss[-2:] if len(ss) >= 2 else ss

    last2 = _last_two_success(candidate)
    speed_kmh = None
    if len(last2) == 2:
        a, b = last2[0], last2[1]
        lat1, lon1, _ = _geo_for_ip(a.ip or "127.0.0.1")
        lat2, lon2, _ = _geo_for_ip(b.ip or "127.0.0.1")
        dist_km = _haversine_km(lat1, lon1, lat2, lon2)
        dt_hours = max((b.ts - a.ts).total_seconds() / 3600.0, 0.05)
        speed_kmh = dist_km / dt_hours

    total, parts, details = risk_engine.score_login(
        cfg=risk_engine.CONFIG,
        recent_rows=candidate,
        login_cities=dict(intel.login_cities or {}),
        login_hours_hist=dict(intel.login_hours_hist or {}),
        device_trust=dict(intel.device_trust or {}),
        ip_city=ip_city,
        is_private_ip=_is_private(cur_ip),
        device_hash=candidate[-1].device_hash,
        known_device=True,  # preview treats last device as known
        ip_changed=False,
        consecutive_fails=0,
        now=datetime.utcnow(),
        last_success_ts=getattr(last_success, "ts", None) if last_success else None,
        speed_kmh=speed_kmh,
        known_device_first_seen=None,
    )
    return {"total": total, "parts": parts, "details": details}

# Risk engine config endpoints (tuning/observability)
@app.get("/risk/config", response_model=schemas.RiskConfigOut)
def get_risk_config():
    return risk_engine.get_config()

@app.put("/risk/config", response_model=schemas.RiskConfigOut)
def put_risk_config(body: schemas.RiskConfigIn):
    updated = risk_engine.update_config(model_to_dict(body, exclude_unset=True))
    # keep in-process thresholds aligned
    global RISK_STEP_UP_THRESHOLD, RISK_HARD_DENY
    RISK_STEP_UP_THRESHOLD = updated["step_up_threshold"]
    RISK_HARD_DENY = updated["hard_deny_threshold"]
    return updated

@app.post("/security/devices/{device_hash}/bind", response_model=schemas.DeviceBindTokenOut)
def bind_device(device_hash: str, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    d = (db.query(models.DeviceFingerprint)
            .filter(models.DeviceFingerprint.user_id == u.id,
                    models.DeviceFingerprint.device_hash == device_hash)
            .first())
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")

    raw = secrets.token_urlsafe(32)  # 256 bits
    d.bind_token_hash = _sha256_hex(raw)
    d.bind_issued_at = datetime.utcnow()
    db.add(d); db.commit()

    return schemas.DeviceBindTokenOut(device_hash=device_hash, device_binding=raw)

@app.post("/security/devices/{device_hash}/unbind", response_model=dict)
def unbind_device(device_hash: str, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    d = (db.query(models.DeviceFingerprint)
            .filter(models.DeviceFingerprint.user_id == u.id,
                    models.DeviceFingerprint.device_hash == device_hash)
            .first())
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    d.bind_token_hash = None
    d.bind_issued_at = None
    d.bind_last_used = None
    db.add(d); db.commit()
    return {"ok": True}

# ML endpoints (unified with loader)
@app.post("/ml/anomaly/train")
def ml_anomaly_train(body: schemas.AnomalyTrainIn,
                     db: Session = Depends(get_db),
                     u: models.User = Depends(current_user)):
    # Use same history loader as scoring; train on ALL history
    hist = _load_tx_rows_for_ml(db, u, drop_newest=False)

    # Build detector with user-provided knobs
    if_cfg = IFConfig(
        contamination = body.contamination if body.contamination is not None else IFConfig().contamination,
        n_estimators  = body.n_estimators  if body.n_estimators  is not None else IFConfig().n_estimators,
        random_state  = body.random_state  if body.random_state  is not None else IFConfig().random_state,
        min_train_rows= body.min_train_rows if body.min_train_rows is not None else IFConfig().min_train_rows,
    )
    ae_cfg = AEConfig(
        min_train_rows = body.min_train_rows if body.min_train_rows is not None else AEConfig().min_train_rows,
        epochs         = body.epochs         if body.epochs         is not None else AEConfig().epochs,
        batch_size     = body.batch_size     if body.batch_size     is not None else AEConfig().batch_size,
        lr             = body.lr             if body.lr             is not None else AEConfig().lr,
        hidden_dim     = body.hidden_dim     if body.hidden_dim     is not None else AEConfig().hidden_dim,
        bottleneck_dim = body.bottleneck_dim if body.bottleneck_dim is not None else AEConfig().bottleneck_dim,
    )

    det = AnomalyDetector(DetectorConfig(method=body.backend, iforest=if_cfg, autoenc=ae_cfg))

    used = body.backend
    n_train = 0
    details: dict = {}
    try:
        if used == "iforest":
            n_train = det.iforest.train(hist)
            details = {"model": "IsolationForest"}
        elif used == "ae":
            n_train = det.autoenc.train(hist)
            details = {"model": "Autoencoder"}
        else:  # auto
            # choose AE if available & enough rows, else iforest
            if len(hist) >= ae_cfg.min_train_rows:
                try:
                    n_train = det.autoenc.train(hist)
                    used = "autoenc"
                    details = {"model": "Autoencoder"}
                except Exception as e:
                    used = "iforest"
                    n_train = det.iforest.train(hist)
                    details = {"model": "IsolationForest", "fallback_reason": str(e)}
            else:
                used = "iforest"
                n_train = det.iforest.train(hist)
                details = {"model": "IsolationForest"}
    except Exception as e:
        return {"ok": False, "backend": used, "n_train": 0, "details": {"reason": str(e)}}

    return {"ok": n_train > 0, "backend": used, "n_train": n_train, "details": details}

@app.post("/ml/anomaly/score")
def ml_anomaly_score(body: schemas.AnomalyScoreIn,
                     db: Session = Depends(get_db),
                     u: models.User = Depends(current_user)):
    hist = _load_tx_rows_for_ml(db, u, drop_newest=False)
    if len(hist) < 1:
        return {"score": 0, "backend": body.backend, "n_train": 0, "details": {"reason": "model_not_trained"}}

    # normalize alias for forcing
    backend = "autoenc" if body.backend == "ae" else body.backend

    det = AnomalyDetector(DetectorConfig())
    used, score, details, n_train = det.train_and_score(hist, {
        "amount": float(body.amount),
        "currency": (body.currency or "").upper(),
        "category": (body.category or "").upper(),
        "merchant": (body.merchant or None),
        "date": None,
    }, force_method=backend)

    return {"score": int(score), "backend": used, "n_train": n_train, "details": details}

def _reason_tokens(reason: Optional[str]) -> List[str]:
    if not reason:
        return []
    toks = []
    for part in reason.split("|"):
        name = part.split("×", 1)[0].strip()
        if name:
            toks.append(name)
    return toks

def _percentile(xs: List[float], p: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (len(s)-1) * (p/100.0)
    f = int(math.floor(k))
    c = min(f+1, len(s)-1)
    if f == c:
        return float(s[int(k)])
    return float(s[f] + (s[c]-s[f]) * (k - f))

@app.get("/logs/summary", response_model=dict)
def logs_summary(
    hours: int = 24,
    top_k: int = 5,
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user)
):
    now = datetime.utcnow()
    start_dt = now - timedelta(hours=max(1, hours))

    rows: List[models.LoginEvent] = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id, models.LoginEvent.ts >= start_dt)
        .order_by(models.LoginEvent.ts.asc())
        .limit(1000)
        .all()
    )

    total = len(rows)
    if total == 0:
        return {
            "window_hours": hours,
            "counts": {"total": 0, "success": 0, "fail": 0, "step_up": 0, "blocks": 0},
            "risk": {"min": 0, "median": 0, "p95": 0},
            "top_cities": [],
            "top_devices": [],
            "top_reasons": [],
            "by_hour": [],
            "narrative": f"No login events in the last {hours}h."
        }

    # aggregates
    success = sum(1 for r in rows if r.success)
    fail = total - success
    step_up = sum(1 for r in rows if (r.risk_score or 0) >= RISK_STEP_UP_THRESHOLD)
    blocks = sum(1 for r in rows if (not r.success) and ((r.risk_score or 0) >= RISK_HARD_DENY or (r.risk_reason or "").startswith("hard_deny")))

    # risk stats
    risks = [int(r.risk_score or 0) for r in rows]
    risk_min = int(min(risks))
    risk_med = int(_median(risks))
    risk_p95 = int(round(_percentile(risks, 95.0)))

    # cities/devices
    cities = []
    dev_counts = Counter()
    for r in rows:
        lat, lon, city = _geo_for_ip((r.ip or "127.0.0.1"))
        cities.append(city)
        if r.device_hash:
            dev_counts[r.device_hash] += 1
    top_cities = [{"city": c, "count": n} for c, n in Counter(cities).most_common(top_k)]

    # device trust lookup
    intel = _get_or_create_intel(db, u.id)
    dev_trust = dict(intel.device_trust or {})
    top_devices = []
    for dh, n in dev_counts.most_common(top_k):
        top_devices.append({"device_hash": dh, "count": n, "trusted": bool(dev_trust.get(dh, False))})

    # reason phrases
    reason_counts = Counter()
    for r in rows:
        for t in _reason_tokens(r.risk_reason):
            reason_counts[t] += 1
    top_reasons = [{"reason": k, "count": v} for k, v in reason_counts.most_common(top_k)]

    # hour-of-day histogram
    by_hour_ctr = Counter([r.ts.hour for r in rows])
    by_hour = [{"hour": h, "count": int(by_hour_ctr.get(h, 0))} for h in range(24)]

    # narrative
    city_snip = ", ".join([f"{c['city']}({c['count']})" for c in top_cities]) or "Unknown"
    dev_snip = ", ".join([f"{d['device_hash'][:10]}…({d['count']})" for d in top_devices]) or "n/a"
    reason_snip = ", ".join([f"{r['reason']}({r['count']})" for r in top_reasons]) or "n/a"

    narrative = (
        f"In the last {hours}h: {total} login(s) "
        f"({success} success, {fail} fail). "
        f"Median risk {risk_med} (p95 {risk_p95}). "
        f"Top cities: {city_snip}. Top devices: {dev_snip}. "
        f"Common drivers: {reason_snip}."
    )

    return {
        "window_hours": hours,
        "counts": {"total": total, "success": success, "fail": fail, "step_up": step_up, "blocks": blocks},
        "risk": {"min": risk_min, "median": risk_med, "p95": risk_p95},
        "top_cities": top_cities,
        "top_devices": top_devices,
        "top_reasons": top_reasons,
        "by_hour": by_hour,
        "narrative": narrative,
    }

@app.get("/logs/search", response_model=dict)
def logs_search(
    q: str,
    limit: int = 50,
    hours: int = 720,         # default last 30 days
    risky_only: bool = False, # only step-up/higher
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user)
):
    query = q.strip().lower()
    terms = [t for t in re.split(r"\s+", query) if t]
    if not terms:
        return {"total": 0, "results": [], "narrative": "Empty query."}

    now = datetime.utcnow()
    start_dt = now - timedelta(hours=max(1, hours))
    rows: List[models.LoginEvent] = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id, models.LoginEvent.ts >= start_dt)
        .order_by(models.LoginEvent.ts.desc())
        .limit(2000)
        .all()
    )

    step_cut = RISK_STEP_UP_THRESHOLD
    def _text_for_row(r: models.LoginEvent) -> str:
        lat, lon, city = _geo_for_ip((r.ip or "127.0.0.1"))
        # searchable surface
        surface = " ".join([
            (r.ip or ""),
            (r.user_agent or ""),
            (r.device_hash or ""),
            (r.risk_reason or ""),
            city or ""
        ]).lower()
        return surface

    matched = []
    for r in rows:
        if risky_only and int(r.risk_score or 0) < step_cut:
            continue
        surface = _text_for_row(r)
        ok = all(t in surface for t in terms)
        if ok:
            lat, lon, city = _geo_for_ip((r.ip or "127.0.0.1"))
            reasons = _reason_tokens(r.risk_reason)
            bucket = ("hard_deny" if (not r.success and (r.risk_reason or "").startswith("hard_deny")
                        or int(r.risk_score or 0) >= RISK_HARD_DENY)
                      else "step_up" if int(r.risk_score or 0) >= step_cut
                      else "normal")
            matched.append({
                "ts": r.ts.isoformat(),
                "ip": r.ip,
                "city": city,
                "device_hash": r.device_hash,
                "success": bool(r.success),
                "risk_score": int(r.risk_score or 0),
                "bucket": bucket,
                "reasons": reasons,
                "risk_reason_raw": r.risk_reason,
            })
        if len(matched) >= max(1, limit):
            break

    narrative = f"Found {len(matched)} event(s) matching '{q}' in the last {hours}h"
    if risky_only:
        narrative += f" (risky only, threshold ≥{step_cut})."
    else:
        narrative += "."

    return {"total": len(matched), "results": matched, "narrative": narrative}
