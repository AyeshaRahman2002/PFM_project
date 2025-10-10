# app/anomaly_engine.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional

import math
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.utils.data as tud
    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest


# Shared featurizer
def _stable_hash(s: Optional[str]) -> int:
    if not s:
        return 0
    # FNV-1a 32-bit
    h = 2166136261
    for ch in s:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return h

def featurize_rows(rows: List[Dict[str, Any]]) -> np.ndarray:
    """
    Convert transaction rows -> numeric feature matrix.
    Features:
      0: log1p(amount)
      1: category_hash_bucket (0..1 normalized)
      2: merchant_hash_bucket (0..1 normalized)
    """
    X = []
    for r in rows:
        amt = float(r.get("amount", 0.0) or 0.0)
        cat = (r.get("category") or "").upper()
        merch = (r.get("merchant") or "").lower()

        log_amt = math.log1p(max(amt, 0.0))
        cat_bucket = _stable_hash(cat) % 1000
        merch_bucket = _stable_hash(merch) % 2000
        X.append([
            log_amt,
            cat_bucket / 999.0,
            merch_bucket / 1999.0,
        ])
    return np.asarray(X, dtype=np.float32)

# Isolation Forest detector
@dataclass
class IFConfig:
    contamination: float = 0.08
    n_estimators: int = 200
    random_state: int = 42
    min_train_rows: int = 10


class IsolationForestDetector:
    def __init__(self, cfg: IFConfig = IFConfig()):
        self.cfg = cfg
        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[IsolationForest] = None

    def train(self, rows: List[Dict[str, Any]]) -> int:
        if len(rows) < self.cfg.min_train_rows:
            self.model = None
            return 0
        X = featurize_rows(rows)
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X)
        self.model = IsolationForest(
            n_estimators=self.cfg.n_estimators,
            contamination=self.cfg.contamination,
            random_state=self.cfg.random_state,
            n_jobs=-1,
        ).fit(Xs)
        return len(rows)

    def score_one(self, row: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        if not self.model or not self.scaler:
            return 0, {"reason": "model_not_trained"}
        X = featurize_rows([row])
        Xs = self.scaler.transform(X)
        # sklearn returns higher score for more normal points.
        raw = self.model.decision_function(Xs)[0]  # higher => more normal
        # Convert to 0..100 anomaly (invert & scale)
        # Typical range ~[-0.5, +0.5]; make robust:
        score = int(np.clip((0.5 - raw) * 100.0, 0.0, 100.0))
        return score, {"raw_score": float(raw)}

# Autoencoder detector (PyTorch)
@dataclass
class AEConfig:
    min_train_rows: int = 40
    epochs: int = 40
    batch_size: int = 64
    lr: float = 1e-3
    hidden_dim: int = 16
    bottleneck_dim: int = 4
    device: str = "cpu"
    score_percentile: float = 95.0  # map recon error to 0..100 via tail


class _AEDataset(tud.Dataset):
    def __init__(self, X: np.ndarray):
        self.X = torch.from_numpy(X.astype(np.float32))

    def __len__(self):
        return self.X.shape[0]

    def __getitem__(self, idx):
        x = self.X[idx]
        return x, x  # input == target

class _AE(nn.Module):
    def __init__(self, in_dim: int, h: int, z: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_dim, h), nn.ReLU(),
            nn.Linear(h, z), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(z, h), nn.ReLU(),
            nn.Linear(h, in_dim),
        )

    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z)

class AutoencoderDetector:
    def __init__(self, cfg: AEConfig = AEConfig()):
        self.cfg = cfg
        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[_AE] = None
        self.thresholds: Dict[str, float] = {}  # percentiles for error score

    def _ensure_torch(self):
        if not TORCH_AVAILABLE:
            raise RuntimeError("PyTorch is not available. Install torch to use autoencoder mode.")

    def train(self, rows: List[Dict[str, Any]]) -> int:
        self._ensure_torch()
        if len(rows) < self.cfg.min_train_rows:
            self.model = None
            return 0

        X = featurize_rows(rows)
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X)

        ds = _AEDataset(Xs)
        dl = tud.DataLoader(ds, batch_size=self.cfg.batch_size, shuffle=True, drop_last=False)

        in_dim = Xs.shape[1]
        self.model = _AE(in_dim, self.cfg.hidden_dim, self.cfg.bottleneck_dim).to(self.cfg.device)
        opt = torch.optim.Adam(self.model.parameters(), lr=self.cfg.lr)
        loss_fn = nn.MSELoss()

        self.model.train()
        for _ in range(self.cfg.epochs):
            for xb, yb in dl:
                xb = xb.to(self.cfg.device)
                yb = yb.to(self.cfg.device)
                opt.zero_grad()
                yhat = self.model(xb)
                loss = loss_fn(yhat, yb)
                loss.backward()
                opt.step()

        # Establish error distribution for mapping
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.from_numpy(Xs).to(self.cfg.device)
            recon = self.model(X_tensor).cpu().numpy()
            err = np.mean((recon - Xs) ** 2, axis=1)  # MSE per-row

        # store percentiles for calibration
        self.thresholds = {
            "p95": float(np.percentile(err, self.cfg.score_percentile)),
            "p99": float(np.percentile(err, 99.0)),
            "median": float(np.percentile(err, 50.0)),
        }
        return len(rows)

    def score_one(self, row: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        self._ensure_torch()
        if not self.model or not self.scaler:
            return 0, {"reason": "model_not_trained"}
        X = featurize_rows([row])
        Xs = self.scaler.transform(X)
        x = torch.from_numpy(Xs.astype(np.float32)).to(self.cfg.device)
        self.model.eval()
        with torch.no_grad():
            y = self.model(x).cpu().numpy()
        err = float(np.mean((y - Xs) ** 2))

        # Map error 0..100 using stored percentiles
        p95 = self.thresholds.get("p95", err)
        p99 = self.thresholds.get("p99", max(err, p95 + 1e-6))
        if err <= p95:
            score = int(np.clip((err / (p95 + 1e-9)) * 50.0, 0.0, 50.0))
        else:
            # between 50..100 as we exceed p95..p99..+
            score = 50 + int(np.clip((err - p95) / (p99 - p95 + 1e-9) * 50.0, 0.0, 50.0))
        return score, {"recon_error": err, **self.thresholds}


# High-level facade
@dataclass
class DetectorConfig:
    method: str = "auto"  # "iforest" | "autoenc" | "auto"
    iforest: IFConfig = IFConfig()
    autoenc: AEConfig = AEConfig()


class AnomalyDetector:
    """
    Train-on-call, stateless facade. Choose between IsolationForest and Autoencoder.
    """
    def __init__(self, cfg: DetectorConfig = DetectorConfig()):
        self.cfg = cfg
        self.iforest = IsolationForestDetector(cfg.iforest)
        self.autoenc = AutoencoderDetector(cfg.autoenc)

    def train_and_score(
        self,
        hist_rows: List[Dict[str, Any]],
        newest_row: Dict[str, Any],
        force_method: Optional[str] = None,
    ) -> Tuple[str, int, Dict[str, Any], int]:
        """
        Returns: (method_used, score(0..100), details, n_train)
        """
        method = (force_method or self.cfg.method or "auto").lower()
        n_train = 0

        def _try_iforest():
            n = self.iforest.train(hist_rows)
            s, d = self.iforest.score_one(newest_row)
            return "iforest", n, s, d

        def _try_autoenc():
            n = self.autoenc.train(hist_rows)
            s, d = self.autoenc.score_one(newest_row)
            return "autoenc", n, s, d

        if method == "iforest":
            used, n_train, score, details = _try_iforest()
            return used, score, details, n_train

        if method == "autoenc":
            # Fall back to iforest if torch missing or too little data
            try:
                used, n_train, score, details = _try_autoenc()
                if n_train == 0:  # not enough rows
                    used, n_train, score, details = _try_iforest()
                return used, score, details, n_train
            except Exception as e:
                # torch not available or training error fallback
                used, n_train, score, details = _try_iforest()
                details = {"fallback": "iforest", "reason": str(e), **details}
                return used, score, details, n_train

        # prefer AE when enough rows and torch is present, else IF
        if TORCH_AVAILABLE and len(hist_rows) >= self.cfg.autoenc.min_train_rows:
            try:
                used, n_train, score, details = _try_autoenc()
                return used, score, details, n_train
            except Exception as e:
                used, n_train, score, details = _try_iforest()
                details = {"fallback": "iforest", "reason": str(e), **details}
                return used, score, details, n_train
        else:
            used, n_train, score, details = _try_iforest()
            return used, score, details, n_train
