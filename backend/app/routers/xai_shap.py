# app/routers/xai_shap.py
import os, time, math, uuid, types
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from functools import lru_cache
from datetime import datetime, timedelta

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, risk_engine
from app.deps import current_user

router = APIRouter(prefix="/xai", tags=["xai"])
ART = Path("./artifacts"); ART.mkdir(parents=True, exist_ok=True)

# Geo config (mirrors main.py)
GEO_PROVIDER = os.getenv("GEO_PROVIDER", "MAXMIND").upper()  # MAXMIND or IPINFO
GEOIP_DB = os.getenv("GEOIP_DB", "./data/GeoLite2-City.mmdb")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", None)


class ExplainRequest(BaseModel):
    # existing preview
    event: Optional[Dict[str, Any]] = None
    save_image: Optional[bool] = False

    # What-if knobs
    ip: Optional[str] = None                    # override current IP
    set_hour: Optional[int] = None              # 0..23
    force_new_device: Optional[bool] = False    # use a new, unseen device hash
    force_known_device: Optional[bool] = None   # force known_device True/False
    consecutive_fails: Optional[int] = None     # inject fail count

    # fabricate a prior success to test travel/city features
    travel_from_ip: Optional[str] = None
    travel_hours_ago: Optional[float] = 1.0

    # history shapers (to light up “zero” features)
    clear_hours_hist: Optional[bool] = False    # make chosen hour uncommon
    clear_city_hist: Optional[bool] = False     # make current city new/rare
    clear_device_trust: Optional[bool] = False  # make device untrusted
    treat_city_as_new: Optional[bool] = False   # just this city unseen
    treat_city_as_rare: Optional[bool] = False  # just this city rare

    # direct feature overrides (after scoring)
    override_features: Optional[Dict[str, float]] = None

    # convenience array - turning features on (set to 1.0) after scoring
    force_features_on: Optional[List[str]] = None


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _is_private_ip(ip: str) -> bool:
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private or (ip or "").startswith("127.")
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
    if _is_private_ip(ip or ""):
        return (0.0, 0.0, "Unknown")
    return _geo_ipinfo(ip) if GEO_PROVIDER == "IPINFO" else _geo_maxmind(ip)


def _last_two_success(evts: List[models.LoginEvent]) -> List[models.LoginEvent]:
    ss = [r for r in evts if r.success]
    return ss[-2:] if len(ss) >= 2 else ss


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    import math as m
    p1, p2 = m.radians(lat1), m.radians(lat2)
    dphi = m.radians(lat2 - lat1)
    dlambda = m.radians(lon2 - lon1)
    a = m.sin(dphi / 2.0) ** 2 + m.cos(p1) * m.cos(p2) * m.sin(dlambda / 2.0) ** 2
    return 2 * R * m.asin(m.sqrt(a))


def _make_waterfall_plot(bias: float, contributions: Dict[str, float], total_logit: float, out_path: Path):
    if not contributions:
        fig, ax = plt.subplots(figsize=(8, 3))
        ax.text(0.5, 0.5, "No numeric contributions", ha="center", va="center", transform=ax.transAxes)
        ax.axis("off")
        fig.savefig(out_path)
        plt.close(fig)
        return

    items = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)
    labels = ["base"] + [k for k, _ in items] + ["final"]

    cumulative = [bias]
    run = bias
    for _, v in items:
        run += v
        cumulative.append(run)
    cumulative.append(total_logit)

    fig, ax = plt.subplots(figsize=(10, 4))
    xs = list(range(len(labels)))
    for i in range(1, len(cumulative)):
        start, end = cumulative[i - 1], cumulative[i]
        height = end - start
        bottom = min(start, end)
        ax.bar(xs[i], abs(height), bottom=bottom, align="center")
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_ylabel("Logit (additive)")
    ax.set_title("Login risk – SHAP-style waterfall (linear model)")
    plt.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def _cfg_to_object(cfg_any: Any) -> Any:
    """Converting dict config to an object with attribute access (cfg.weights)."""
    if isinstance(cfg_any, dict):
        ns = types.SimpleNamespace(**cfg_any)
        setattr(ns, "weights", cfg_any.get("weights", {}))
        return ns
    return cfg_any


def _geo_valid(lat: float, lon: float, name: str) -> bool:
    """Treating Unknown or (0,0) as invalid geolocation."""
    if not name or name.strip().lower() == "unknown":
        return False
    if abs(lat) < 1e-9 and abs(lon) < 1e-9:
        return False
    return True


@router.post("/explain_login")
def explain_login(
    req: ExplainRequest,
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    """
    Explain a login's risk score using linear contributions (= weights × features).
    Supports what-if controls + feature overrides.
    """
    # config/weights
    raw_cfg = risk_engine.get_config()
    cfg_obj = _cfg_to_object(raw_cfg)
    weights = dict(getattr(cfg_obj, "weights", {}) or {})
    bias = float(weights.get("bias", 0.0))

    # base history
    rows: List[models.LoginEvent] = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id)
        .order_by(models.LoginEvent.ts.asc())
        .all()
    )
    if not rows:
        raise HTTPException(status_code=400, detail="No login events to explain.")

    # building candidate with preview + optional fabricated prior success
    from copy import deepcopy
    candidate = rows[:]
    template = rows[-1]
    now = datetime.utcnow()

    if req.travel_from_ip:
        prior = deepcopy(template)
        prior.success = True
        prior.ip = req.travel_from_ip
        prior.ts = now - timedelta(hours=max(0.05, float(req.travel_hours_ago or 1.0)))
        candidate.append(prior)

    e = deepcopy(template)
    e.success = True
    e.ts = now

    if req.event:
        if "ip" in req.event and req.event["ip"]:
            e.ip = req.event["ip"]
        if "device_hash" in req.event and req.event["device_hash"]:
            e.device_hash = req.event["device_hash"]

    if req.ip:
        e.ip = req.ip
    if req.set_hour is not None:
        h = int(max(0, min(23, req.set_hour)))
        e.ts = e.ts.replace(hour=h, minute=0, second=0, microsecond=0)
    if req.force_new_device:
        e.device_hash = f"sim-{uuid.uuid4().hex[:16]}"

    candidate.append(e)

    # user intel
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

    if getattr(req, "clear_hours_hist", False):
        login_hours_hist = {str(h): 0 for h in range(24)}
    if getattr(req, "clear_city_hist", False):
        login_cities = {}
    if getattr(req, "clear_device_trust", False):
        device_trust = {}

    cur_ip = (candidate[-1].ip if candidate else "127.0.0.1") or "127.0.0.1"
    lat, lon, ip_city = _geo_for_ip(cur_ip)
    using_private_ip = _is_private_ip(cur_ip)
    geo_ok = _geo_valid(lat, lon, ip_city)

    if getattr(req, "treat_city_as_new", False):
        login_cities.pop(ip_city, None)
    if getattr(req, "treat_city_as_rare", False):
        login_cities[ip_city] = max(0, min(1, int(login_cities.get(ip_city, 0))))

    last_success = next((r for r in reversed(candidate) if r.success), None)
    last2 = _last_two_success(candidate)
    speed_kmh = None
    if len(last2) == 2:
        a, b = last2[0], last2[1]
        lat1, lon1, name1 = _geo_for_ip(a.ip or "127.0.0.1")
        lat2, lon2, name2 = _geo_for_ip(b.ip or "127.0.0.1")
        if _geo_valid(lat1, lon1, name1) and _geo_valid(lat2, lon2, name2):
            dist_km = _haversine_km(lat1, lon1, lat2, lon2)
            dt_hours = max((b.ts - a.ts).total_seconds() / 3600.0, 0.05)
            speed_kmh = dist_km / dt_hours

    prev_ip = (last_success.ip if last_success else "") or ""
    ip_changed = (prev_ip.strip() != (cur_ip or "").strip())

    dev_hash = candidate[-1].device_hash
    if req.force_known_device is not None:
        known = bool(req.force_known_device)
    else:
        known = False
        if dev_hash:
            known = (
                db.query(models.DeviceFingerprint)
                .filter(
                    models.DeviceFingerprint.user_id == u.id,
                    models.DeviceFingerprint.device_hash == dev_hash,
                )
                .first()
                is not None
            )

    consecutive_fails = int(req.consecutive_fails) if req.consecutive_fails is not None else 0

    ip_city_for_engine = ip_city if geo_ok else ""

    # score to recover features
    total_score, parts, details = risk_engine.score_login(
        cfg=cfg_obj,
        recent_rows=candidate,
        login_cities=login_cities,
        login_hours_hist=login_hours_hist,
        device_trust=device_trust,
        ip_city=ip_city_for_engine,
        is_private_ip=_is_private_ip(cur_ip),
        device_hash=dev_hash,
        known_device=known,
        ip_changed=ip_changed,
        consecutive_fails=consecutive_fails,
        now=datetime.utcnow(),
        last_success_ts=getattr(last_success, "ts", None) if last_success else None,
        speed_kmh=speed_kmh,
        known_device_first_seen=None,
    )

    features = dict((details or {}).get("features") or {})
    if not features:
        raise HTTPException(status_code=500, detail="No numeric features produced by risk engine.")

    # post-scoring overrides
    force_on = set(getattr(req, "force_features_on", []) or [])
    overrides = dict(getattr(req, "override_features", {}) or {})
    for k in force_on:
        overrides.setdefault(k, 1.0)
    for k, v in overrides.items():
        if isinstance(v, bool):
            features[k] = 1.0 if v else 0.0
        elif isinstance(v, (int, float)):
            features[k] = float(v)

    # contributions for ALL weight keys (bias excluded)
    contributions: Dict[str, float] = {}
    total_logit = bias

    for fname, w in weights.items():
        if fname == "bias":
            continue
        fv_raw = features.get(fname, 0)
        if isinstance(fv_raw, bool):
            fv = 1.0 if fv_raw else 0.0
        elif isinstance(fv_raw, (int, float)):
            fv = float(fv_raw)
        else:
            fv = 0.0
        c = float(w) * fv
        contributions[fname] = c
        total_logit += c

    prob = _sigmoid(total_logit)

    # optional waterfall image
    img_path = None
    if req.save_image:
        p = ART / f"xai_login_{int(time.time())}.png"
        try:
            _make_waterfall_plot(bias, contributions, total_logit, p)
            img_path = str(p.resolve())
        except Exception as e:
            img_path = f"error_generating_image: {e}"

    # alignment & debug
    weight_keys = {k for k in weights.keys() if k != "bias"}
    feature_keys = set(features.keys())
    weights_not_in_features = sorted(list(weight_keys - feature_keys))
    features_not_in_weights = sorted(list(feature_keys - weight_keys))

    contrib_list = [
        {
            "feature": k,
            "value": float(
                features.get(k, 0) if isinstance(features.get(k, 0), (int, float))
                else (1.0 if features.get(k, 0) is True else 0.0)
            ),
            "weight": float(weights.get(k, 0.0)),
            "contribution": float(v),
        }
        for k, v in sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)
    ]

    why_zero = {}
    for k in weight_keys:
        wt = float(weights.get(k, 0.0))
        val_raw = features.get(k, 0.0)
        val = float(val_raw if isinstance(val_raw, (int, float)) else (1.0 if val_raw is True else 0.0))
        if wt == 0.0 or val == 0.0:
            reason = []
            if wt == 0.0: reason.append("weight=0")
            if val == 0.0: reason.append("value=0")
            why_zero[k] = {"weight": wt, "value": val, "reason": " & ".join(reason) or "n/a"}

    return {
        "base_logit": bias,
        "base_probability": _sigmoid(bias),
        "total_logit": total_logit,
        "probability": prob,
        "contribs": contrib_list,
        "weights_snapshot": weights,
        "features_snapshot": features,
        "feature_alignment": {
            "weights_not_in_features": weights_not_in_features,
            "features_not_in_weights": features_not_in_weights,
        },
        "waterfall_image": img_path,
        "raw_score_parts": parts,
        "raw_score_details": details,
        "why_zero": why_zero,
        "what_if_echo": {
            "using_private_ip": using_private_ip,
            "ip": req.ip,
            "set_hour": req.set_hour,
            "force_new_device": req.force_new_device,
            "force_known_device": req.force_known_device,
            "consecutive_fails": consecutive_fails,
            "travel_from_ip": req.travel_from_ip,
            "travel_hours_ago": req.travel_hours_ago,
            "clear_hours_hist": getattr(req, "clear_hours_hist", False),
            "clear_city_hist": getattr(req, "clear_city_hist", False),
            "clear_device_trust": getattr(req, "clear_device_trust", False),
            "treat_city_as_new": getattr(req, "treat_city_as_new", False),
            "treat_city_as_rare": getattr(req, "treat_city_as_rare", False),
            "override_features": overrides,
            "geo_provider": GEO_PROVIDER,
            "ip_city": ip_city,
            "geo_ok": geo_ok,
            "geo_latlon": [lat, lon],
            "speed_kmh": None if speed_kmh is None else round(speed_kmh, 1),
            "prev_ip": prev_ip,
            "ip_changed": ip_changed,
        },
    }
