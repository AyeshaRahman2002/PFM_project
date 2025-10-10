# app/routers/metrics.py
from __future__ import annotations
from fastapi import APIRouter, Response
from typing import Dict, Any
import time, math

try:
    import psutil  # optional
    _HAS_PSUTIL = True
except Exception:
    _HAS_PSUTIL = False

router = APIRouter(prefix="/metrics", tags=["metrics"])

_METRICS: Dict[str, Any] = {
    "started_at": time.time(),
    "request_count": 0,
    "error_count": 0,
    "in_flight": 0,
    "latencies_ms": [],   # rolling buffer
    "lat_cap": 5000,
    "last_reset": time.time(),
}

def _percentile(xs, p):
    if not xs: return 0.0
    s = sorted(xs)
    k = (len(s)-1) * (p/100.0)
    f = math.floor(k); c = min(f+1, len(s)-1)
    return float(s[int(k)]) if f == c else float(s[f] + (s[c]-s[f])*(k-f))

@router.get("/system")
def system_metrics():
    if _HAS_PSUTIL:
        mem = psutil.virtual_memory()
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.3),
            "memory_percent": mem.percent,
            "memory_used_gb": round(mem.used/1024**3, 3),
            "memory_total_gb": round(mem.total/1024**3, 3),
            "uptime_seconds": int(time.time() - psutil.boot_time()),
            "process_count": len(psutil.pids()),
        }
    return {"note": "Install psutil for system metrics: pip install psutil"}

@router.get("/app")
def app_metrics():
    now = time.time()
    dur = max(now - _METRICS["last_reset"], 1e-6)
    reqs, errs = int(_METRICS["request_count"]), int(_METRICS["error_count"])
    lat = list(_METRICS["latencies_ms"])
    rps = reqs / dur
    avg = (sum(lat)/len(lat)) if lat else 0.0
    p95 = _percentile(lat, 95.0)
    p99 = _percentile(lat, 99.0)
    err_rate = (errs/reqs) if reqs else 0.0
    return {
        "since": int(_METRICS["last_reset"]),
        "uptime_seconds": int(now - _METRICS["started_at"]),
        "requests_total": reqs,
        "errors_total": errs,
        "in_flight": int(_METRICS["in_flight"]),
        "rps": round(rps, 2),
        "avg_latency_ms": round(avg, 2),
        "p95_latency_ms": round(p95, 2),
        "p99_latency_ms": round(p99, 2),
        "error_rate": round(err_rate, 4),
        "latency_samples": len(lat),
    }

@router.post("/reset")
def reset_app_metrics():
    _METRICS.update({
        "request_count": 0, "error_count": 0, "in_flight": 0,
        "latencies_ms": [], "last_reset": time.time(),
    })
    return {"ok": True}

@router.get("/prom")
def prom_text():
    now = time.time()
    dur = max(now - _METRICS["last_reset"], 1e-6)
    reqs, errs = int(_METRICS["request_count"]), int(_METRICS["error_count"])
    lat = list(_METRICS["latencies_ms"])
    rps = reqs / dur
    avg = (sum(lat)/len(lat)) if lat else 0.0
    p95 = _percentile(lat, 95.0)
    p99 = _percentile(lat, 99.0)
    lines = [
        "# HELP app_requests_total Total requests processed",
        "# TYPE app_requests_total counter",
        f"app_requests_total {reqs}",
        "# HELP app_errors_total Total error responses",
        "# TYPE app_errors_total counter",
        f"app_errors_total {errs}",
        "# HELP app_in_flight Current in-flight requests",
        "# TYPE app_in_flight gauge",
        f"app_in_flight {_METRICS['in_flight']}",
        "# HELP app_rps Requests per second",
        "# TYPE app_rps gauge",
        f"app_rps {rps}",
        "# HELP app_latency_ms_avg Average latency (ms)",
        "# TYPE app_latency_ms_avg gauge",
        f"app_latency_ms_avg {avg}",
        "# HELP app_latency_ms_p95 95th percentile latency (ms)",
        "# TYPE app_latency_ms_p95 gauge",
        f"app_latency_ms_p95 {p95}",
        "# HELP app_latency_ms_p99 99th percentile latency (ms)",
        "# TYPE app_latency_ms_p99 gauge",
        f"app_latency_ms_p99 {p99}",
    ]
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
