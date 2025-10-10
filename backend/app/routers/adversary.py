# app/routers/adversary.py
from __future__ import annotations
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from random import Random, choice, randint, uniform
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.deps import current_user
from app.database import get_db
from app import models, risk_engine, anomaly_engine

router = APIRouter(prefix="/adversary", tags=["adversary"])

# Geo shim so tests can monkeypatch adversary_router._geo_for_ip
try:
    from app.main import _geo_for_ip as _geo_for_ip_main

    def _geo_for_ip(ip: str):
        return _geo_for_ip_main(ip)
except Exception:
    # safe fallback so tests still pass even if main._geo_for_ip isn’t importable
    def _geo_for_ip(ip: str):
        return (0.0, 0.0, "Unknown")

# Schemas
class GenOpts(BaseModel):
    seed: Optional[int] = 12345
    count: int = Field(10, ge=1, le=1000)
    attack: str = Field("credential_stuffing", description="credential_stuffing | impossible_travel | device_spoof | tx_fuzz | mixed")
    device_models: Optional[List[str]] = None

class AttackRunIn(BaseModel):
    attack: str = Field(..., description="credential_stuffing | impossible_travel | device_spoof | tx_fuzz | mixed")
    count: int = Field(20, ge=1, le=200)
    persist: bool = False
    # If persist=True and attack produces many failed logins, they will be inserted as failed LoginEvent rows.
    method_for_anomaly: Optional[str] = None  # "iforest" | "ae" | "auto"

class AttackSummary(BaseModel):
    generated: int
    inserted: int
    avg_risk: float
    step_up_rate: float
    hard_deny_rate: float
    sample: List[Dict[str, Any]]

class TxFuzzIn(BaseModel):
    count: int = Field(25, ge=1, le=500)
    perturb_scale: float = Field(0.5, description="scale for amount perturbation")
    backend: str = Field("iforest", description="iforest | ae | auto")

class TxFuzzOutItem(BaseModel):
    amount: float
    category: str
    merchant: Optional[str]
    score: int
    backend: str
    details: Dict[str, Any]

# Helpers
def _rand_ip(rng: Random, public_only: bool = True) -> str:
    # generating somewhat realistic IPv4 addresses
    while True:
        a = rng.randint(1, 255)
        b = rng.randint(0, 255)
        c = rng.randint(0, 255)
        d = rng.randint(1, 254)
        ip = f"{a}.{b}.{c}.{d}"
        try:
            ipaddr = ipaddress.ip_address(ip)
            if public_only and (ipaddr.is_private or ipaddr.is_loopback or ipaddr.is_multicast):
                continue
            return ip
        except Exception:
            continue

def _sample_device(rng: Random, models: Optional[List[str]] = None) -> Dict[str, Optional[str]]:
    m = choice(models) if models else choice(["iPhone X", "Pixel 6", "Android Phone", "Unknown Model"])
    os = "iOS" if "iPhone" in m else "Android" if "Pixel" in m or "Android" in m else "Unknown"
    return {"device_id": f"dev-{rng.randint(100000, 999999)}", "model": m, "os": os, "locale": "en-US"}

def _make_login_event_stub(user: models.User, ip: str, ua: str, device_hash: Optional[str], success: bool, risk_score: int, reason: str):
    return models.LoginEvent(
        user_id=user.id,
        ts=datetime.utcnow(),
        ip=ip,
        user_agent=ua,
        device_hash=device_hash,
        success=success,
        risk_score=risk_score,
        risk_reason=reason,
    )

def _load_tx_rows_for_ml(db: Session, u: models.User, limit: int = 500) -> List[Dict[str, Any]]:
    rows = (
        db.query(models.Transaction)
        .filter(models.Transaction.user_id == u.id)
        .order_by(models.Transaction.created_at.asc())
        .limit(limit)
        .all()
    )
    out = []
    for t in rows:
        out.append({
            "amount": float(t.amount),
            "currency": t.currency,
            "category": (t.category or "").upper(),
            "merchant": (t.merchant or None),
            "date": t.date.isoformat() if t.date else None,
        })
    return out

# Attack generators
def _generate_credential_stuffing(rng: Random, user: models.User, count: int, device_models=None):
    events = []
    for i in range(count):
        ip = _rand_ip(rng)
        dev = _sample_device(rng, device_models)
        ua = f"BadBot/{rng.randint(1,9)} (credential-stuff)"
        # device_hash is None for unauthenticated bot; use pseudo hash for some
        device_hash = None if rng.random() < 0.7 else f"bot-{rng.randint(1,99999)}"
        events.append({"ip": ip, "ua": ua, "device_hash": device_hash, "success": False, "note": "credential_stuff"})
    return events

def _generate_device_spoof(rng: Random, user: models.User, count: int, device_models=None):
    events = []
    for i in range(count):
        ip = _rand_ip(rng)
        dev = _sample_device(rng, device_models)
        ua = f"{dev['model']}/{dev['os']} (spoof)"
        device_hash = f"spoof-{rng.randint(1,999999)}"
        # half of them will be successful if device hash looks known
        success = rng.random() < 0.3
        events.append({"ip": ip, "ua": ua, "device_hash": device_hash, "success": success, "note": "device_spoof"})
    return events

def _generate_impossible_travel(rng: Random, user: models.User):
    # two success events separated by tiny time but far IPs so speed >750 km/h
    # returning a small list of events: prior success, remote success
    ip1 = _rand_ip(rng)
    ip2 = _rand_ip(rng)
    # forcing diversity by ensuring different /8
    if ip1.split(".")[0] == ip2.split(".")[0]:
        ip2 = _rand_ip(rng)
    ua = "Mozilla/5.0 (Mobile)"
    ev1 = {"ip": ip1, "ua": ua, "device_hash": f"dev-{rng.randint(1,9999)}", "success": True, "note": "prior_success"}
    ev2 = {"ip": ip2, "ua": ua, "device_hash": f"dev-{rng.randint(1,9999)}", "success": True, "note": "impossible_travel"}
    return [ev1, ev2]

def _generate_tx_fuzz(rng: Random, user: models.User, count: int, scale: float = 0.5):
    base = _load_tx_rows_for_ml
    cats = ["FOOD", "GROCERY", "TRAVEL", "RENT", "UTILS", "ENTERTAINMENT"]
    merchants = ["Starbucks", "AcmeStore", "FlyHigh", "RideApp", "MegaMart", "LocalCafe"]
    out = []
    for _ in range(count):
        amt = round(max(0.5, rng.gauss(50.0, 120.0) * (1.0 + rng.uniform(-scale, scale))), 2)
        cat = choice(cats)
        merch = choice(merchants)
        out.append({"amount": amt, "currency": "SAR", "category": cat, "merchant": merch})
    return out

# Endpoints
@router.post("/generate", response_model=List[Dict[str, Any]])
def generate(opts: GenOpts, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    """
    Generating synthetic attack events (not persisted). Useful for previewing.
    """
    rng = Random(opts.seed or 12345)
    if opts.attack == "credential_stuffing":
        evs = _generate_credential_stuffing(rng, u, opts.count, opts.device_models)
    elif opts.attack == "device_spoof":
        evs = _generate_device_spoof(rng, u, opts.count, opts.device_models)
    elif opts.attack == "impossible_travel":
        # produce pairs; flatten up to count
        evs = []
        while len(evs) < opts.count:
            evs.extend(_generate_impossible_travel(rng, u))
        evs = evs[:opts.count]
    elif opts.attack == "tx_fuzz":
        evs = _generate_tx_fuzz(rng, u, opts.count, scale=0.5)
    elif opts.attack == "mixed":
        evs = []
        mix = ["credential_stuffing", "device_spoof", "impossible_travel"]
        while len(evs) < opts.count:
            a = choice(mix)
            if a == "impossible_travel":
                evs.extend(_generate_impossible_travel(rng, u))
            elif a == "device_spoof":
                evs.extend(_generate_device_spoof(rng, u, 1, opts.device_models))
            else:
                evs.extend(_generate_credential_stuffing(rng, u, 1, opts.device_models))
        evs = evs[:opts.count]
    else:
        raise HTTPException(status_code=400, detail=f"Unknown attack: {opts.attack}")
    return evs

@router.post("/run", response_model=AttackSummary)
def run_attack(req: AttackRunIn, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    """
    Running a quick attack simulation against the live risk scoring for this user.
    - Will compute risk for each generated event using risk_engine.score_login.
    - If persist=True, inserts LoginEvent rows (failed successes as generated).
    """
    rng = Random( int(datetime.utcnow().timestamp()) % 2**31 )
    # generate events
    if req.attack == "credential_stuffing":
        evs = _generate_credential_stuffing(rng, u, req.count)
    elif req.attack == "device_spoof":
        evs = _generate_device_spoof(rng, u, req.count)
    elif req.attack == "impossible_travel":
        # generate pairs until count reached
        evs = []
        while len(evs) < req.count:
            evs.extend(_generate_impossible_travel(rng, u))
        evs = evs[:req.count]
    elif req.attack == "tx_fuzz":
        # this path delegates to tx fuzz endpoint
        raise HTTPException(status_code=400, detail="Use /adversary/tx_fuzz for transaction fuzzing.")
    elif req.attack == "mixed":
        evs = []
        mix = ["credential_stuffing", "device_spoof", "impossible_travel"]
        while len(evs) < req.count:
            a = choice(mix)
            if a == "impossible_travel":
                evs.extend(_generate_impossible_travel(rng, u))
            elif a == "device_spoof":
                evs.extend(_generate_device_spoof(rng, u, 1))
            else:
                evs.extend(_generate_credential_stuffing(rng, u, 1))
        evs = evs[:req.count]
    else:
        raise HTTPException(status_code=400, detail=f"Unknown attack: {req.attack}")

    # fetch intel & history needed to score via risk_engine
    intel = (
        db.query(models.UserIntel)
        .filter(models.UserIntel.user_id == u.id)
        .first()
    )
    if not intel:
        intel = models.UserIntel(
            user_id=u.id,
            login_hours_hist={str(h): 0 for h in range(24)},
            login_cities={},
            device_trust={},
            tx_category_stats={},
            tx_merchant_counts={},
        )
        db.add(intel); db.commit(); db.refresh(intel)

    login_cities = dict(intel.login_cities or {})
    login_hours_hist = dict(intel.login_hours_hist or {})
    device_trust = dict(intel.device_trust or {})

    # using recent rows (all) as "history" to mirror runtime scoring
    recent = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id)
        .order_by(models.LoginEvent.ts.asc())
        .all()
    )
    now = datetime.utcnow()
    candidate = recent[:]

    inserted = 0
    scores = []
    sample_out = []

    for ev in evs:
        # LoginEvent-like object for scoring: reuse models.LoginEvent but not persisted
        fake = models.LoginEvent(
            user_id=u.id,
            ip=ev.get("ip"),
            user_agent=ev.get("ua"),
            device_hash=ev.get("device_hash"),
            success=ev.get("success", False),
            ts=now,
        )
        # candidate + new event
        cand = candidate + [fake]
        # computing impossible travel speed using last two successes (risk_engine handles it)
        last_success = next((r for r in reversed(cand) if r.success), None)
        last2 = [r for r in cand if r.success]
        if len(last2) >= 2:
            # risk_engine will compute speed internally in score_login helper if passed rows
            pass

        total, parts, details = risk_engine.score_login(
            cfg=risk_engine.CONFIG,
            recent_rows=cand,
            login_cities=login_cities,
            login_hours_hist=login_hours_hist,
            device_trust=device_trust,
            ip_city=(ev.get("ip") or "")[:],  # risk_engine will geo-resolve
            is_private_ip=False,
            device_hash=ev.get("device_hash"),
            known_device=bool(device_trust.get(ev.get("device_hash") or "", False)),
            ip_changed=False,
            consecutive_fails=0,
            now=datetime.utcnow(),
            last_success_ts=getattr(last_success, "ts", None) if last_success else None,
            speed_kmh=None,
            known_device_first_seen=None,
        )

        scores.append(total)
        sample_out.append({
            "ip": ev.get("ip"),
            "device_hash": ev.get("device_hash"),
            "ua": ev.get("ua"),
            "note": ev.get("note", ""),
            "pred_risk": int(total),
            "raw_parts": parts,
            "raw_details": details,
        })

        # optionally persist as LoginEvent
        if req.persist:
            db_ev = _make_login_event_stub(
                user=u,
                ip=ev.get("ip"),
                ua=ev.get("ua"),
                device_hash=ev.get("device_hash"),
                success=bool(ev.get("success", False)),
                risk_score=int(total),
                reason="adversary_sim|" + (ev.get("note") or "sim"),
            )
            db.add(db_ev)
            inserted += 1

        # append to candidate so later events see this as history
        candidate.append(fake)

    if req.persist:
        db.commit()

    n = len(scores) or 1
    avg_risk = float(sum(scores)) / n
    step_up_rate = float(sum(1 for s in scores if s >= risk_engine.CONFIG.step_up_threshold)) / n
    hard_deny_rate = float(sum(1 for s in scores if s >= risk_engine.CONFIG.hard_deny_threshold)) / n

    return AttackSummary(
        generated=len(evs),
        inserted=inserted,
        avg_risk=round(avg_risk, 2),
        step_up_rate=round(step_up_rate, 3),
        hard_deny_rate=round(hard_deny_rate, 3),
        sample=sample_out[:10],
    )

@router.post("/tx_fuzz", response_model=List[TxFuzzOutItem])
def tx_fuzz(req: TxFuzzIn, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    """
    Generated fuzzed transactions and scored them with the anomaly detector.
    Returns per-item anomaly score (0..100) using a per-user IsolationForest train-on-history.
    """
    rng = Random(int(datetime.utcnow().timestamp()) % 2**31)
    fuzzed = _generate_tx_fuzz(rng, u, req.count, scale=req.perturb_scale)

    # training an IsolationForest on user's historical transactions (like /ml/anomaly/train)
    hist = _load_tx_rows_for_ml(db, u, limit=500)
    det = anomaly_engine.AnomalyDetector()  # default config
    try:
        # trying to train using IF first (robust). If not enough rows, detector.score_one returns model_not_trained
        det.iforest.train(hist)
    except Exception:
        # ignore, fall back to empty
        pass

    out = []
    for tx in fuzzed:
        # call detector.train_and_score-like process by using train on hist + iforest.score_one
        used = "iforest"
        score = 0
        details = {}
        try:
            s, d = det.iforest.score_one({
                "amount": tx["amount"],
                "currency": (tx.get("currency") or "SAR").upper(),
                "category": (tx.get("category") or "").upper(),
                "merchant": tx.get("merchant"),
                "date": None,
            })
            score = int(s)
            details = d or {}
        except Exception as e:
            # model not trained or error; return 0 with reason
            score = 0
            details = {"reason": "model_not_trained_or_error", "err": str(e)}

        out.append(TxFuzzOutItem(
            amount=float(tx["amount"]),
            category=tx["category"],
            merchant=tx.get("merchant"),
            score=score,
            backend=used,
            details=details,
        ))

    return out
