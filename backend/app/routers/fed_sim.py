# app/routers/fed_sim.py
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import math, re, time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import models, risk_engine
from app.deps import current_user
from app.database import get_db

router = APIRouter(prefix="/fed/sim", tags=["fed-sim"])

# Matches parts emitted by risk_engine.linear_score: "name × +w -> +contrib"
_CONTRIB_RE = re.compile(r"([a-z_]+)\s*\*\s*([+\-]?\d+(?:\.\d+)?)\s*->\s*([+\-]?\d+(?:\.\d+)?)")
_REASON_RE = re.compile(r"([a-z_]+)")

def _extract_feats(reason_raw: Optional[str]) -> List[Tuple[str, float]]:
    """
    Parse 'name × w -> contrib' to recover feature magnitude v = contrib / w.
    Falls back to (name, 1.0) for tokens we can't parse (e.g., 'hard_deny').
    """
    feats: List[Tuple[str, float]] = []
    for piece in (reason_raw or "").split("|"):
        m = _CONTRIB_RE.search(piece)
        if m:
            name = m.group(1)
            w = float(m.group(2))
            contrib = float(m.group(3))
            v = (contrib / w) if abs(w) > 1e-9 else 1.0
            feats.append((name, v))
        else:
            m2 = _REASON_RE.search(piece)
            if m2:
                feats.append((m2.group(1), 1.0))
    return feats

def _sigmoid(x: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0

def _score_feats(weights: Dict[str, float], feats: List[Tuple[str, float]]) -> int:
    """
    Compute risk%=round(100*sigmoid(bias + Σ w_k * v_k))
    """
    z = float(weights.get("bias", 0.0))
    for name, v in feats:
        z += float(weights.get(name, 0.0)) * float(v)
    p = _sigmoid(z)
    return int(round(100.0 * p))

class FedEvalIn(BaseModel):
    hours: int = 168
    step_up: int = 60
    hard_deny: int = 90
    limit: int = 1000
    # Optional time guard (seconds) so we never “run forever”
    max_seconds: float = 10.0
    # If omitted, A = current live weights; B = latest sim weights if available, else A
    weights_a: Optional[Dict[str, float]] = None
    weights_b: Optional[Dict[str, float]] = None

class Confusion(BaseModel):
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    rate_predicted: float  # fraction predicted positive
    rate_observed: float   # fraction observed positive

class FedEvalOut(BaseModel):
    hours: int
    totals: Dict[str, int]
    step_threshold: int
    block_threshold: int
    a: Dict[str, Any]
    b: Dict[str, Any]
    delta: Dict[str, Any]
    changed_examples: List[Dict[str, Any]]
    best_step_a: Optional[Dict[str, Any]] = None
    best_step_b: Optional[Dict[str, Any]] = None
    best_block_a: Optional[Dict[str, Any]] = None
    best_block_b: Optional[Dict[str, Any]] = None
    narrative: str

def _finalize_confusion(bucket_dict: Dict[str, int], obs_positive_count: int, n: int) -> Dict[str, Any]:
    tp = bucket_dict["tp"]; fp = bucket_dict["fp"]; tn = bucket_dict["tn"]; fn = bucket_dict["fn"]
    prec = (tp / (tp + fp)) if (tp + fp) else 0.0
    rec  = (tp / (tp + fn)) if (tp + fn) else 0.0
    rate_pred = ((tp + fp) / n) if n else 0.0
    rate_obs  = (obs_positive_count / n) if n else 0.0
    return Confusion(
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=round(prec, 3),
        recall=round(rec, 3),
        rate_predicted=round(rate_pred, 3),
        rate_observed=round(rate_obs, 3)
    ).model_dump()

def _best_threshold(pred_scores: List[int], obs_labels: List[bool]) -> Dict[str, Any]:
    """
    Sweep 0..100 and return the cut with max F1 (ties keep lowest threshold).
    """
    best = {"thr": 0, "precision": 0.0, "recall": 0.0, "f1": 0.0}
    if not pred_scores or not obs_labels or len(pred_scores) != len(obs_labels):
        return best
    for t in range(0, 101):
        tp = fp = fn = 0
        for s, y in zip(pred_scores, obs_labels):
            p = s >= t
            if p and y: tp += 1
            elif p and not y: fp += 1
            elif (not p) and y: fn += 1
        prec = (tp / (tp + fp)) if (tp + fp) else 0.0
        rec  = (tp / (tp + fn)) if (tp + fn) else 0.0
        f1 = (2*prec*rec)/(prec+rec) if (prec+rec) else 0.0
        if f1 > best["f1"]:
            best = {"thr": t, "precision": round(prec,3), "recall": round(rec,3), "f1": round(f1,3)}
    return best

@router.post("/eval", response_model=FedEvalOut)
def eval_weights(payload: FedEvalIn,
                 db: Session = Depends(get_db),
                 u: models.User = Depends(current_user)):

    start_time = time.time()

    # choose weight sets
    wa = payload.weights_a or dict(risk_engine.CONFIG.weights or {})
    # Trying to pull latest simulated weights from the fed router module if present
    try:
        from app.routers import fed as fed_router_module  # has FED_STATE
        sim_state = getattr(fed_router_module, "FED_STATE", {})
        cand = payload.weights_b if payload.weights_b is not None else sim_state.get("weights")
        wb = dict(cand or risk_engine.CONFIG.weights or {})
    except Exception:
        wb = payload.weights_b or wa

    # fetch recent events for this user
    cutoff = datetime.utcnow() - timedelta(hours=max(1, payload.hours))
    rows: List[models.LoginEvent] = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id, models.LoginEvent.ts >= cutoff)
        .order_by(models.LoginEvent.ts.asc())
        .limit(max(1, payload.limit))
        .all()
    )
    if not rows:
        raise HTTPException(status_code=404, detail=f"No events in the last {payload.hours}h.")

    def observed_labels(r: models.LoginEvent) -> Tuple[bool, bool]:
        risk = int(r.risk_score or 0)
        block = (not r.success) and ((r.risk_reason or "").startswith("hard_deny") or risk >= payload.hard_deny)
        step = risk >= payload.step_up
        return step, block

    A = {"step": {"tp":0,"fp":0,"tn":0,"fn":0}, "block": {"tp":0,"fp":0,"tn":0,"fn":0}, "avg_risk": 0.0}
    B = {"step": {"tp":0,"fp":0,"tn":0,"fn":0}, "block": {"tp":0,"fp":0,"tn":0,"fn":0}, "avg_risk": 0.0}
    changed: List[Dict[str, Any]] = []

    # Collect per-event score vectors to enable threshold sweeps
    preds_a_step: List[int] = []
    preds_b_step: List[int] = []
    preds_a_block: List[int] = []
    preds_b_block: List[int] = []
    obs_steps: List[bool] = []
    obs_blocks: List[bool] = []

    for idx, r in enumerate(rows, 1):
        # soft time guard
        if time.time() - start_time > payload.max_seconds:
            break

        feats = _extract_feats(r.risk_reason)
        ra = _score_feats(wa, feats)
        rb = _score_feats(wb, feats)

        step_obs, block_obs = observed_labels(r)
        step_a, block_a = (ra >= payload.step_up), (ra >= payload.hard_deny)
        step_b, block_b = (rb >= payload.step_up), (rb >= payload.hard_deny)

        for pred, obs, bucket in [(step_a, step_obs, "step"), (block_a, block_obs, "block")]:
            if pred and obs:   A[bucket]["tp"] += 1
            elif pred and not obs: A[bucket]["fp"] += 1
            elif (not pred) and (not obs): A[bucket]["tn"] += 1
            else: A[bucket]["fn"] += 1

        for pred, obs, bucket in [(step_b, step_obs, "step"), (block_b, block_obs, "block")]:
            if pred and obs:   B[bucket]["tp"] += 1
            elif pred and not obs: B[bucket]["fp"] += 1
            elif (not pred) and (not obs): B[bucket]["tn"] += 1
            else: B[bucket]["fn"] += 1

        A["avg_risk"] += ra
        B["avg_risk"] += rb

        # for sweeps
        preds_a_step.append(ra); preds_b_step.append(rb)
        preds_a_block.append(ra); preds_b_block.append(rb)
        obs_steps.append(step_obs); obs_blocks.append(block_obs)

        if (step_a != step_b) or (block_a != block_b):
            changed.append({
                "ts": r.ts.isoformat(),
                "device": (r.device_hash or "")[:10] + ("…" if r.device_hash and len(r.device_hash)>10 else ""),
                "tokens": [n for n, _ in feats],
                "risk_a": ra, "risk_b": rb,
                "step_a": step_a, "step_b": step_b,
                "block_a": block_a, "block_b": block_b,
                "obs_step": step_obs, "obs_block": block_obs
            })

    n = (A["step"]["tp"] + A["step"]["fp"] + A["step"]["tn"] + A["step"]["fn"])
    if n == 0:
        raise HTTPException(status_code=422, detail="Evaluation aborted by time guard; try lowering 'limit' or raising 'max_seconds'.")

    A["avg_risk"] = round(A["avg_risk"] / n, 2)
    B["avg_risk"] = round(B["avg_risk"] / n, 2)

    # observed counts from stored outcomes (fixed thresholds)
    obs_step_count  = sum(1 for r in rows[:n] if int(r.risk_score or 0) >= payload.step_up)
    obs_block_count = sum(1 for r in rows[:n] if (not r.success) and (((r.risk_reason or "").startswith("hard_deny")) or int(r.risk_score or 0) >= payload.hard_deny))

    out_a = {
        "avg_risk": A["avg_risk"],
        "step": _finalize_confusion(A["step"], obs_step_count, n),
        "block": _finalize_confusion(A["block"], obs_block_count, n),
    }
    out_b = {
        "avg_risk": B["avg_risk"],
        "step": _finalize_confusion(B["step"], obs_step_count, n),
        "block": _finalize_confusion(B["block"], obs_block_count, n),
    }

    delta = {
        "avg_risk": round(out_b["avg_risk"] - out_a["avg_risk"], 2),
        "step_rate": round(out_b["step"]["rate_predicted"] - out_a["step"]["rate_predicted"], 3),
        "block_rate": round(out_b["block"]["rate_predicted"] - out_a["block"]["rate_predicted"], 3),
    }

    changed.sort(key=lambda x: (x["block_b"] != x["block_a"], x["step_b"] != x["step_a"], abs(x["risk_b"]-x["risk_a"])), reverse=True)
    examples = changed[:10]

    # threshold sweeps (suggested thresholds that maximize F1 on the window)
    best_step_a = _best_threshold(preds_a_step, obs_steps)
    best_step_b = _best_threshold(preds_b_step, obs_steps)
    best_block_a = _best_threshold(preds_a_block, obs_blocks)
    best_block_b = _best_threshold(preds_b_block, obs_blocks)

    narrative = (
        f"Evaluated {n} events over last {payload.hours}h. "
        f"A(avg risk {out_a['avg_risk']}) -> B(avg risk {out_b['avg_risk']}, delta {delta['avg_risk']:+}). "
        f"Step-up rate delta {delta['step_rate']:+.3f}, Block rate delta {delta['block_rate']:+.3f}."
    )

    return FedEvalOut(
        hours=payload.hours,
        totals={"events": n, "obs_step": obs_step_count, "obs_block": obs_block_count},
        step_threshold=payload.step_up,
        block_threshold=payload.hard_deny,
        a=out_a,
        b=out_b,
        delta=delta,
        changed_examples=examples,
        best_step_a=best_step_a or None,
        best_step_b=best_step_b or None,
        best_block_a=best_block_a or None,
        best_block_b=best_block_b or None,
        narrative=narrative,
    )
