# app/risk_engine.py
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
import math

@dataclass
class RiskConfig:
    weights: Dict[str, float] = field(default_factory=lambda: {
        "bias": -1.5,
        "new_device": 2.2,
        "untrusted_device": 1.6,
        "ip_changed": 0.6,
        "new_city": 1.0,
        "rare_city": 0.5,
        "odd_hour": 0.4,
        "uncommon_hour": 0.25,
        "impossible_travel": 2.4,
        "consecutive_fails": 0.65,
        "no_prior_success_cap": 0.0,
        "device_age_decay": 0.0,
    })
    scale: float = 1.0
    intercept: float = 0.0
    step_up_threshold: int = 60
    hard_deny_threshold: int = 90

CONFIG = RiskConfig()

def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    else:
        z = math.exp(x)
        return z / (1.0 + z)

def _z(v: float, mean: float, mad: float) -> float:
    if mad <= 1e-6:
        return 0.0
    return abs(v - mean) / mad

def login_features(
    *,
    recent_rows: List[Any],
    login_cities: Dict[str, int],
    login_hours_hist: Dict[str, int],
    device_trust: Dict[str, bool],
    ip_city: str,
    is_private_ip: bool,
    device_hash: Optional[str],
    known_device: bool,
    ip_changed: bool,
    consecutive_fails: int,
    now: datetime,
    last_success_ts: Optional[datetime],
    speed_kmh: Optional[float],
) -> Tuple[Dict[str, float], Dict[str, Any]]:
    f: Dict[str, float] = {}
    notes: Dict[str, Any] = {}

    f["new_device"] = 1.0 if device_hash and not known_device else 0.0
    trusted = bool(device_trust.get(device_hash or "", False))
    f["untrusted_device"] = 1.0 if not trusted else 0.0

    f["ip_changed"] = 1.0 if ip_changed else 0.0
    dev_like = is_private_ip or ip_city == "Unknown"
    notes["city"] = ip_city

    prior_successes = sum(1 for r in recent_rows[:-1] if getattr(r, "success", False))
    notes["prior_successes"] = prior_successes
    if not dev_like and prior_successes >= 1:
        seen_city = int(login_cities.get(ip_city, 0))
        f["new_city"] = 1.0 if seen_city == 0 else 0.0
        f["rare_city"] = 1.0 if (seen_city <= 2 and seen_city > 0) else 0.0
    else:
        f["new_city"] = 0.0
        f["rare_city"] = 0.0

    if prior_successes >= 3:
        hh = str(now.hour)
        hour_count = int(login_hours_hist.get(hh, 0))
        f["odd_hour"] = 1.0 if hour_count == 0 else 0.0
        f["uncommon_hour"] = 1.0 if (hour_count <= 2 and hour_count > 0) else 0.0
        notes["hour_count"] = hour_count
    else:
        f["odd_hour"] = 0.0
        f["uncommon_hour"] = 0.0

    if speed_kmh is not None and speed_kmh > 750.0:
        f["impossible_travel"] = 1.0
    else:
        f["impossible_travel"] = 0.0
    notes["speed_kmh"] = round(speed_kmh, 1) if speed_kmh is not None else None

    f["consecutive_fails"] = float(max(consecutive_fails, 0))
    notes["last_success_ts"] = last_success_ts.isoformat() if last_success_ts else None
    return f, notes

def linear_score(features: Dict[str, float], cfg: RiskConfig) -> Tuple[int, List[str]]:
    s = cfg.weights.get("bias", 0.0)
    parts: List[str] = []
    for k, v in features.items():
        w = cfg.weights.get(k, 0.0)
        if v != 0.0 and w != 0.0:
            parts.append(f"{k} × {w:+.2f} -> {v*w:+.2f}")
        s += w * v
    s = cfg.scale * s + cfg.intercept
    p = _sigmoid(s)
    total = max(0, min(int(round(p * 100)), 100))
    return total, parts

def apply_post_rules(
    total: int,
    *,
    prior_successes: int,
    known_device_first_seen: Optional[datetime],
    now: datetime,
) -> int:
    if prior_successes == 0:
        total = min(total, 55)
    if known_device_first_seen:
        days = max((now - known_device_first_seen).days, 0)
        half_life = 30.0
        factor = 0.5 ** (days / half_life)
        total = int(round(total * factor)) if days > 0 else total
    return max(0, min(total, 100))

def score_login(
    *,
    cfg: RiskConfig,
    recent_rows: List[Any],
    login_cities: Dict[str, int],
    login_hours_hist: Dict[str, int],
    device_trust: Dict[str, bool],
    ip_city: str,
    is_private_ip: bool,
    device_hash: Optional[str],
    known_device: bool,
    ip_changed: bool,
    consecutive_fails: int,
    now: datetime,
    last_success_ts: Optional[datetime],
    speed_kmh: Optional[float],
    known_device_first_seen: Optional[datetime],
) -> Tuple[int, List[str], Dict[str, Any]]:
    feats, notes = login_features(
        recent_rows=recent_rows,
        login_cities=login_cities,
        login_hours_hist=login_hours_hist,
        device_trust=device_trust,
        ip_city=ip_city,
        is_private_ip=is_private_ip,
        device_hash=device_hash,
        known_device=known_device,
        ip_changed=ip_changed,
        consecutive_fails=consecutive_fails,
        now=now,
        last_success_ts=last_success_ts,
        speed_kmh=speed_kmh,
    )
    total, parts = linear_score(feats, cfg)
    total = apply_post_rules(
        total,
        prior_successes=notes.get("prior_successes", 0),
        known_device_first_seen=known_device_first_seen,
        now=now,
    )
    return total, parts, {"features": feats, **notes}

def get_config() -> Dict[str, Any]:
    return {
        "weights": dict(CONFIG.weights),
        "scale": CONFIG.scale,
        "intercept": CONFIG.intercept,
        "step_up_threshold": CONFIG.step_up_threshold,
        "hard_deny_threshold": CONFIG.hard_deny_threshold,
    }

def update_config(new_cfg: Dict[str, Any]) -> Dict[str, Any]:
    if "weights" in new_cfg and isinstance(new_cfg["weights"], dict):
        CONFIG.weights.update({k: float(v) for k, v in new_cfg["weights"].items()})
    if "scale" in new_cfg:
        CONFIG.scale = float(new_cfg["scale"])
    if "intercept" in new_cfg:
        CONFIG.intercept = float(new_cfg["intercept"])
    if "step_up_threshold" in new_cfg:
        CONFIG.step_up_threshold = int(new_cfg["step_up_threshold"])
    if "hard_deny_threshold" in new_cfg:
        CONFIG.hard_deny_threshold = int(new_cfg["hard_deny_threshold"])
    return get_config()
