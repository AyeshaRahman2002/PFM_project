# app/models.py
from sqlalchemy import Column, Integer, String, Date, DateTime, ForeignKey, Numeric, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base
from sqlalchemy import JSON

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # profile
    first_name = Column(String, nullable=True)
    last_name  = Column(String, nullable=True)
    dob        = Column(Date, nullable=True)
    nationality = Column(String, nullable=True)
    avatar_url  = Column(String, nullable=True)

    # ATO protection
    failed_attempts = Column(Integer, default=0)
    lock_until      = Column(DateTime, nullable=True)

    # MFA (TOTP)
    mfa_totp_secret = Column(String, nullable=True)
    mfa_enabled     = Column(Boolean, default=False)
    mfa_verified_at = Column(DateTime, nullable=True)

    transactions = relationship("Transaction", back_populates="user", cascade="all,delete")
    budgets = relationship("Budget", back_populates="user", cascade="all,delete")
    goals = relationship("Goal", back_populates="user", cascade="all,delete")
    devices = relationship("DeviceFingerprint", back_populates="user", cascade="all,delete")
    login_events = relationship("LoginEvent", back_populates="user", cascade="all,delete")

class StepUpChallenge(Base):
    __tablename__ = "step_up_challenges"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    method = Column(String, nullable=False)  # "totp"
    challenge_id = Column(String, unique=True, index=True)  # uuid
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used_at    = Column(DateTime, nullable=True)
    meta = Column(JSON, nullable=True)

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    amount = Column(Numeric(12,2), nullable=False)
    currency = Column(String, default="SAR")
    category = Column(String, index=True, nullable=False)
    date = Column(Date, nullable=False)
    merchant = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="transactions")

class Budget(Base):
    __tablename__ = "budgets"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    category = Column(String, index=True, nullable=False)
    amount = Column(Numeric(12,2), nullable=False)
    month = Column(Integer, nullable=False)
    year = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="budgets")

class Goal(Base):
    __tablename__ = "goals"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    name = Column(String, nullable=False)
    target_amount = Column(Numeric(12,2), nullable=False)
    target_date = Column(Date, nullable=False)
    current_amount = Column(Numeric(12,2), nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="goals")

class DeviceFingerprint(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    device_hash = Column(String, index=True, nullable=False)
    label = Column(String, nullable=True)
    trusted = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen  = Column(DateTime, default=datetime.utcnow)
    last_ip    = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    # Binding token (store only hash)
    bind_token_hash = Column(String, nullable=True, index=True)
    bind_issued_at  = Column(DateTime, nullable=True)
    bind_last_used  = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="devices")

class LoginEvent(Base):
    __tablename__ = "login_events"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    ts = Column(DateTime, default=datetime.utcnow)
    ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    device_hash = Column(String, nullable=True)
    success = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    risk_reason = Column(String, nullable=True)
    user = relationship("User", back_populates="login_events")

class Session(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    session_id = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen  = Column(DateTime, default=datetime.utcnow)
    device_hash = Column(String, nullable=True)
    ip = Column(String, nullable=True)
    revoked = Column(Boolean, default=False)

class RecoveryCode(Base):
    __tablename__ = "recovery_codes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    code_hash = Column(String, index=True)
    used_at   = Column(DateTime, nullable=True)

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    ts = Column(DateTime, default=datetime.utcnow)
    type = Column(String)
    ip = Column(String, nullable=True)
    device_hash = Column(String, nullable=True)
    meta = Column(JSON, nullable=True)

class UserIntel(Base):
    __tablename__ = "user_intel"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True)
    login_hours_hist = Column(JSON, default=dict)
    login_cities = Column(JSON, default=dict)
    device_trust = Column(JSON, default=dict)
    tx_category_stats = Column(JSON, default=dict)
    tx_merchant_counts = Column(JSON, default=dict)

    user = relationship("User")
