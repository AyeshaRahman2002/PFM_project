# app/routers/fed.py
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Literal
from random import Random, gauss
import math

from app.deps import current_user
from app.database import get_db
from sqlalchemy.orm import Session
from app import models, risk_engine

router = APIRouter(prefix="/fed", tags=["fed"])

# Internal sim state (in-memory)
FED_STATE: Dict[str, Any] = {
    "running": False,
    "config": {},
    "round": 0,
    "total_rounds": 0,
    "clients": 0,
    "weights": {},     # latest global weights
    "history": [],     # per-round metrics
    "dp": {},
    "feature_names": [],
}

# Feature space (aligned with risk_engine)
FEAT_NAMES: List[str] = [
    "bias",
    "new_device",
    "untrusted_device",
    "ip_changed",
    "new_city",
    "rare_city",
    "odd_hour",
    "uncommon_hour",
    "impossible_travel",
    "consecutive_fails",
]

def _sigmoid(x: float) -> float:
    # guard against overflow
    if x > 35:  # 1.0 within float eps
        return 1.0
    if x < -35:
        return 0.0
    return 1.0 / (1.0 + math.exp(-x))

def _dot(w: Dict[str, float], x: Dict[str, float]) -> float:
    return sum(w.get(k, 0.0) * float(x.get(k, 0.0)) for k in FEAT_NAMES)

def _logloss(p: float, y: int) -> float:
    p = min(max(p, 1e-9), 1 - 1e-9)
    return -(y * math.log(p) + (1 - y) * math.log(1 - p))

def _risk_cfg_to_weights() -> Dict[str, float]:
    cfg = risk_engine.get_config()
    w = dict(cfg["weights"] or {})
    # Ensure we have all features
    for k in FEAT_NAMES:
        if k not in w:
            w[k] = 0.0
    return {k: float(v) for k, v in w.items() if k in FEAT_NAMES}

def _zero_weights() -> Dict[str, float]:
    return {k: 0.0 for k in FEAT_NAMES}

def _copy_weights(w: Dict[str, float]) -> Dict[str, float]:
    return {k: float(v) for k, v in w.items()}

def _add_weights(a: Dict[str, float], b: Dict[str, float]) -> Dict[str, float]:
    return {k: float(a.get(k, 0.0)) + float(b.get(k, 0.0)) for k in FEAT_NAMES}

def _scale_weights(w: Dict[str, float], s: float) -> Dict[str, float]:
    return {k: float(v) * s for k, v in w.items()}

def _sub_weights(a: Dict[str, float], b: Dict[str, float]) -> Dict[str, float]:
    return {k: float(a.get(k, 0.0)) - float(b.get(k, 0.0)) for k in FEAT_NAMES}

def _l2_norm(w: Dict[str, float]) -> float:
    return math.sqrt(sum((w[k] ** 2) for k in FEAT_NAMES))

def _clip_l2(delta: Dict[str, float], clip: float) -> Dict[str, float]:
    n = _l2_norm(delta)
    if n <= clip or clip <= 0:
        return delta
    scale = clip / max(n, 1e-12)
    return _scale_weights(delta, scale)

# Data synthesis
def _sample_example(rng: Random, client_bias: float) -> Dict[str, float]:
    """
    Draw a synthetic login example's feature vector.
    Features are mostly 0/1, except consecutive_fails in [0..3].
    client_bias shifts base rates per client.
    """
    x = {k: 0.0 for k in FEAT_NAMES}
    x["bias"] = 1.0
    # base probabilities (toy)
    p = {
        "new_device":        0.06 + client_bias,
        "untrusted_device":  0.12 + client_bias/2.0,
        "ip_changed":        0.18,
        "new_city":          0.04,
        "rare_city":         0.01,
        "odd_hour":          0.25,
        "uncommon_hour":     0.12,
        "impossible_travel": 0.004,
    }
    for k, base in p.items():
        x[k] = 1.0 if rng.random() < max(0.0, min(1.0, base)) else 0.0
    # consecutive fails: skewed small integers
    r = rng.random()
    if r < 0.80: cf = 0
    elif r < 0.92: cf = 1
    elif r < 0.98: cf = 2
    else: cf = 3
    x["consecutive_fails"] = float(cf)
    return x

def _make_dataset(rng: Random, n: int, w_true: Dict[str, float], client_bias: float) -> List[Dict[str, Any]]:
    data: List[Dict[str, Any]] = []
    for _ in range(n):
        x = _sample_example(rng, client_bias)
        # Generate label with logistic model around true weights
        margin = _dot(w_true, x)
        # Slight server noise for label realism
        prob = _sigmoid(margin - 0.5 + rng.uniform(-0.1, 0.1))
        y = 1 if rng.random() < prob else 0
        data.append({"x": x, "y": y})
    return data

def _evaluate(weights: Dict[str, float], data: List[Dict[str, Any]]) -> Dict[str, float]:
    if not data:
        return {"loss": 0.0, "acc": 1.0}
    loss = 0.0
    correct = 0
    for row in data:
        p = _sigmoid(_dot(weights, row["x"]))
        loss += _logloss(p, row["y"])
        pred = 1 if p >= 0.5 else 0
        correct += 1 if pred == row["y"] else 0
    n = float(len(data))
    return {"loss": loss / n, "acc": correct / n}

# Training (local SGD with optional FedProx)
def _local_train(
    start_w: Dict[str, float],
    data: List[Dict[str, Any]],
    lr: float,
    epochs: int,
    rng: Random,
    prox_mu: float = 0.0,
) -> Dict[str, float]:
    """
    One client's local training.
    If prox_mu>0, add FedProx proximal term pulling toward start_w.
    """
    w = _copy_weights(start_w)
    mu = float(max(0.0, prox_mu))
    for _ in range(max(1, epochs)):
        for row in data:
            x = row["x"]; y = row["y"]
            p = _sigmoid(_dot(w, x))
            # gradient of logloss wrt weights = (p - y)*x
            grad = {k: (p - y) * x.get(k, 0.0) for k in FEAT_NAMES}
            # FedProx / L2-to-prior
            if mu > 0.0:
                for k in FEAT_NAMES:
                    grad[k] += mu * (w[k] - start_w.get(k, 0.0))
            # SGD update
            for k in FEAT_NAMES:
                w[k] -= lr * grad[k]
        # tiny weight decay to keep numbers tame
        for k in FEAT_NAMES:
            w[k] *= 0.999
    return w

# DP wrapper on client update
def _dp_secure_update(
    w_global: Dict[str, float],
    w_local: Dict[str, float],
    clip: float,
    sigma: float,
    rng: Random
) -> Dict[str, float]:
    """
    Produce a DP-noised local model as (w_global + clipped+noised delta).
    """
    delta = _sub_weights(w_local, w_global)
    delta = _clip_l2(delta, clip) if clip > 0 else delta
    noisy = {k: delta[k] + (gauss(0.0, sigma) if sigma > 0 else 0.0) for k in FEAT_NAMES}
    return _add_weights(w_global, noisy)

# Schemas
class FedStartIn(BaseModel):
    clients: int = Field(5, ge=2, le=50)
    rounds: int = Field(5, ge=1, le=50)
    local_epochs: int = Field(2, ge=1, le=10)
    lr: float = Field(0.2, gt=0, le=1.0)
    model: Literal["risk_lr"] = "risk_lr"
    # Initialization & regularization knobs
    init_from_live: bool = Field(True, description="Start global weights from current live config (else zeros)")
    prox_mu: float = Field(0.0, ge=0.0, le=1.0, description="FedProx proximal strength (0 disables)")
    # Differential Privacy (toy)
    dp: bool = False
    dp_clip: float = Field(1.0, ge=0.0, description="L2 clipping of client deltas")
    dp_sigma: float = Field(0.2, ge=0.0, description="Gaussian noise std for DP")

class FedStatusOut(BaseModel):
    running: bool
    round: int
    total_rounds: int
    clients: int
    model: str
    dp: Dict[str, Any]
    weights: Dict[str, float]
    history: List[Dict[str, Any]]
    narrative: str

class FedApplyOut(BaseModel):
    applied: bool
    new_weights: Dict[str, float]
    note: str

# Endpoints
@router.post("/sim/start", response_model=FedStatusOut)
def start_sim(
    body: FedStartIn,
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    """
    Synchronous FedAvg simulation over synthetic, per-client login data.
    Trains a tiny logistic model on risk features and returns per-round metrics.
    """
    rng = Random(42)  # reproducible demo

    # True weights = current risk config (acts as the "world" that generates labels)
    w_true = _risk_cfg_to_weights()

    # Init global weights (optionally from live, else zeros)
    w_global = _risk_cfg_to_weights() if body.init_from_live else _zero_weights()

    # Build per-client datasets + a server eval set
    clients = max(2, body.clients)
    rounds = body.rounds
    local_epochs = body.local_epochs
    lr = body.lr

    client_data: List[List[Dict[str, Any]]] = []
    for i in range(clients):
        # give each client a slightly different base rate
        bias = rng.uniform(-0.02, 0.05) + (i / max(1, clients - 1)) * 0.03
        client_data.append(_make_dataset(Random(1000 + i), n=200, w_true=w_true, client_bias=bias))

    eval_data = _make_dataset(Random(999), n=400, w_true=w_true, client_bias=0.02)

    history: List[Dict[str, Any]] = []

    for r in range(1, rounds + 1):
        agg_sum = _zero_weights()
        for i in range(clients):
            w_local = _local_train(
                w_global,
                client_data[i],
                lr=lr,
                epochs=local_epochs,
                rng=Random(2000 + 10*i + r),
                prox_mu=body.prox_mu,
            )
            if body.dp:
                w_local = _dp_secure_update(
                    w_global, w_local,
                    clip=body.dp_clip, sigma=body.dp_sigma,
                    rng=Random(3000 + i*r)
                )
            agg_sum = _add_weights(agg_sum, w_local)

        # FedAvg
        w_global = _scale_weights(agg_sum, 1.0 / float(clients))

        # Evaluate on server set
        eval_metrics = _evaluate(w_global, eval_data)
        history.append({
            "round": r,
            "loss": round(eval_metrics["loss"], 4),
            "acc": round(eval_metrics["acc"], 4),
        })

    # Stash state
    FED_STATE.update({
        "running": False,
        "config": body.dict(),
        "round": rounds,
        "total_rounds": rounds,
        "clients": clients,
        "weights": w_global,
        "history": history,
        "dp": {"enabled": body.dp, "clip": body.dp_clip, "sigma": body.dp_sigma},
        "feature_names": FEAT_NAMES[:],
    })

    narrative = (
        f"FedAvg finished: {clients} clients × {rounds} rounds, "
        f"{local_epochs} local epoch(s), lr={lr}. Eval acc={history[-1]['acc'] if history else 0:.3f}."
    )

    return FedStatusOut(
        running=False,
        round=rounds,
        total_rounds=rounds,
        clients=clients,
        model=body.model,
        dp=FED_STATE["dp"],
        weights=FED_STATE["weights"],
        history=history,
        narrative=narrative,
    )

@router.get("/sim/status", response_model=FedStatusOut)
def sim_status(
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    if not FED_STATE.get("history"):
        return FedStatusOut(
            running=False,
            round=0,
            total_rounds=0,
            clients=0,
            model="risk_lr",
            dp={"enabled": False},
            weights=_zero_weights(),
            history=[],
            narrative="No simulation has been run yet.",
        )
    return FedStatusOut(
        running=False,
        round=int(FED_STATE["round"]),
        total_rounds=int(FED_STATE["total_rounds"]),
        clients=int(FED_STATE["clients"]),
        model="risk_lr",
        dp=FED_STATE["dp"],
        weights=FED_STATE["weights"],
        history=FED_STATE["history"],
        narrative=f"Last round={FED_STATE['round']}, eval acc={FED_STATE['history'][-1]['acc']:.3f}.",
    )

@router.post("/sim/apply", response_model=FedApplyOut)
def sim_apply_weights(
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    """
    Apply the latest global weights to the live risk engine config.
    (This overwrites the current weights; thresholds/scale/intercept are left as-is.)
    """
    if not FED_STATE.get("weights"):
        return FedApplyOut(applied=False, new_weights={}, note="No simulation weights to apply.")

    new_w = _copy_weights(FED_STATE["weights"])
    # ensure keys exist
    cfg = risk_engine.get_config()
    merged = dict(cfg["weights"])
    for k in FEAT_NAMES:
        merged[k] = float(new_w.get(k, 0.0))

    # Commit via existing update endpoint helper
    risk_engine.update_config({"weights": merged})

    return FedApplyOut(applied=True, new_weights=merged, note="Applied federated weights to risk engine.")
