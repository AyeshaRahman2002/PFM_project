# app/schemas.py
from pydantic import BaseModel, EmailStr, Field
from datetime import date, datetime
from typing import Optional, List, Literal, Dict, Any

# Profile
class ProfileIn(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    dob: Optional[date] = None
    nationality: Optional[str] = None
    avatar_url: Optional[str] = None

class ProfileOut(ProfileIn):
    email: EmailStr

# Auth
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: EmailStr
    avatar_url: Optional[str] = None
    class Config:
        orm_mode = True  # works on Pydantic v1; v2 will warn but still works

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    risk_score: int = 0
    step_up_required: bool = False
    message: Optional[str] = None
    refresh_token: Optional[str] = None
    pending_challenge: Optional[str] = None

# Transactions
class TxCreate(BaseModel):
    amount: float
    currency: str = "SAR"
    category: str
    date: date
    merchant: Optional[str] = None
    notes: Optional[str] = None

class TxOut(TxCreate):
    id: int
    class Config:
        orm_mode = True

# Budgets
class BudgetCreate(BaseModel):
    category: str
    amount: float
    month: int = Field(ge=1, le=12)
    year: int

class BudgetOut(BaseModel):
    id: int
    category: str
    amount: float
    month: int
    year: int
    class Config:
        orm_mode = True

# Goals
class GoalCreate(BaseModel):
    name: str
    target_amount: float
    target_date: date

class GoalContribute(BaseModel):
    amount: float

class GoalOut(BaseModel):
    id: int
    name: str
    target_amount: float
    target_date: date
    current_amount: float
    class Config:
        orm_mode = True

# Insights
class SummaryOut(BaseModel):
    total_spent: float
    top_categories: List[tuple]

# Security DTOs
class DeviceIn(BaseModel):
    model: Optional[str] = None
    os: Optional[str] = None
    app_version: Optional[str] = None
    timezone: Optional[str] = None
    locale: Optional[str] = None
    device_id: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    device: Optional[DeviceIn] = None
    device_binding: Optional[str] = None

class DeviceBindTokenOut(BaseModel):
    device_hash: str
    device_binding: str

class DeviceOut(BaseModel):
    device_hash: str
    label: Optional[str] = None
    trusted: bool
    first_seen: datetime
    last_seen: datetime
    last_ip: Optional[str] = None
    user_agent: Optional[str] = None

class LoginEventOut(BaseModel):
    ts: datetime
    ip: Optional[str]
    user_agent: Optional[str]
    device_hash: Optional[str]
    success: bool
    risk_score: int
    risk_reason: Optional[str]

class SessionOut(BaseModel):
    session_id: str
    created_at: datetime
    last_seen: datetime
    device_hash: Optional[str] = None
    ip: Optional[str] = None
    revoked: bool

class IntelProfileOut(BaseModel):
    login_hours_hist: dict
    login_cities: dict
    device_trust: dict
    tx_category_stats: dict
    tx_merchant_counts: dict

class TxScoreIn(BaseModel):
    amount: float
    currency: str = "SAR"
    category: str
    merchant: Optional[str] = None

class ScoreBreakdown(BaseModel):
    total: int
    parts: list
    details: dict = {}

class LoginScoreIn(BaseModel):
    ip: Optional[str] = None
    device_hash: Optional[str] = None
    user_agent: Optional[str] = None

class StepUpStartIn(BaseModel):
    method: Literal["totp", "push", "webauthn"]

class StepUpChallengeOut(BaseModel):
    challenge_id: str
    method: str
    expires_at: datetime

class StepUpVerifyIn(BaseModel):
    challenge_id: str
    code: Optional[str] = None  # for TOTP; push/WebAuthn don't need it

class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str

# Risk engine config (tuning/observability)
class RiskConfigIn(BaseModel):
    weights: Optional[Dict[str, float]] = None
    scale: Optional[float] = None
    intercept: Optional[float] = None
    step_up_threshold: Optional[int] = None
    hard_deny_threshold: Optional[int] = None

class RiskConfigOut(BaseModel):
    weights: Dict[str, float]
    scale: float
    intercept: float
    step_up_threshold: int
    hard_deny_threshold: int

# ML (anomaly)
class AnomalyTrainIn(BaseModel):
    backend: Literal["iforest", "ae", "auto"] = "auto"
    contamination: Optional[float] = None   # iforest
    n_estimators: Optional[int] = None      # iforest
    random_state: Optional[int] = None      # iforest
    min_train_rows: Optional[int] = None    # both
    epochs: Optional[int] = None            # ae
    hidden_dim: Optional[int] = None        # ae
    bottleneck_dim: Optional[int] = None    # ae
    lr: Optional[float] = None              # ae
    batch_size: Optional[int] = None        # ae

class AnomalyScoreIn(BaseModel):
    backend: Literal["iforest", "ae", "auto"] = "auto"
    amount: float
    currency: str = "SAR"
    category: str
    merchant: Optional[str] = None
