# app/routers/soc.py
from fastapi import APIRouter, Query
from typing import List, Dict, Any
import time, uuid
from app import threat_intel as ti

router = APIRouter(prefix="/soc", tags=["soc"])

ALERTS: List[Dict[str, Any]] = []

def _normalize_alert(evt: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(evt or {})

    # id
    out["id"] = out.get("id") or uuid.uuid4().hex

    # timestamp normalization (prefer seconds)
    ts = out.get("timestamp") or out.get("ts") or out.get("time") or out.get("ts_epoch") or out.get("ts_ms")
    if ts is None:
        ts = int(time.time())
    else:
        # try to coerce various formats
        try:
            if isinstance(ts, str):
                # try ISO
                from datetime import datetime
                ts = int(datetime.fromisoformat(ts).timestamp())
            else:
                # numeric: if looks like ms, convert to s
                ts = float(ts)
                if ts > 1_000_000_000_000:  # clearly ms
                    ts = ts / 1000.0
                elif ts > 10_000_000_000:   # maybe ms (near future seconds otherwise)
                    ts = ts / 1000.0
                ts = int(ts)
        except Exception:
            ts = int(time.time())
    out["timestamp"] = ts

    # simple defaults
    out["ip"] = out.get("ip") or ""
    out["user"] = out.get("user") or ""
    out["event"] = out.get("event") or "unknown"
    try:
        out["score"] = int(out.get("score", 0) or 0)
    except Exception:
        out["score"] = 0

    return out

@router.post("/alert")
def create_alert(event: Dict[str, Any]):
    """Ingest a new alert from risk model output"""
    ALERTS.append(_normalize_alert(event))
    # keeping only last N in memory if you like
    if len(ALERTS) > 10000:
        del ALERTS[:-10000]
    return {"status": "ok", "count": len(ALERTS)}

@router.get("/alerts")
def list_alerts(limit: int = Query(50, ge=1, le=1000)):
    """Fetch latest alerts for dashboard display"""
    # ensure sorted newest-first
    return sorted(ALERTS, key=lambda e: e.get("timestamp", 0), reverse=True)[:limit]

@router.get("/recheck_ip")
def recheck_ip(ip: str):
    """SOC analyst can manually requery TI"""
    return ti.lookup_ip(ip)
