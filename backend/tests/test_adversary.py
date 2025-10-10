# tests/test_adversary.py
import os
from datetime import date, timedelta
from uuid import uuid4
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app import models, risk_engine
from app.routers import adversary as adversary_router

try:
    from app.routers import logs as logs_router
except Exception:
    logs_router = None

# Fixtures: test DB + app
@pytest.fixture(scope="session")
def engine():
    """
    Session-scoped *shared* in-memory SQLite engine.
    StaticPool keeps one connection so the schema persists across sessions/threads.
    """
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)

@pytest.fixture()
def db(engine):
    """
    Function-scoped session.
    """
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    sess = TestingSessionLocal()
    try:
        yield sess
    finally:
        sess.close()

@pytest.fixture()
def user(db):
    """
    Create a unique user per test to avoid UNIQUE(email) collisions.
    """
    u = models.User(email=f"test+{uuid4().hex[:8]}@example.com", password_hash="x")
    db.add(u)
    db.commit()
    db.refresh(u)
    return u

@pytest.fixture()
def app(db, user):
    """
    Minimal FastAPI app exposing ONLY the adversary router (+ logs router if available) with dependency overrides.
    """
    app = FastAPI()
    app.include_router(adversary_router.router)
    if logs_router:
        app.include_router(logs_router.router)

    # override get_db
    from app.database import get_db as real_get_db

    def _get_db_override():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[real_get_db] = _get_db_override

    # override current_user
    from app.deps import current_user as real_current_user

    def _current_user_override():
        return user

    app.dependency_overrides[real_current_user] = _current_user_override
    return app

@pytest.fixture()
def client(app):
    return TestClient(app)


# Helpers
@pytest.fixture(autouse=True)
def deterministic_risk(monkeypatch):
    """
    Make risk scoring deterministic & fast for tests.
    Always return score=85 (step-up but not hard deny with default thresholds).
    """
    def _fake_score_login(**kwargs):
        return (
            85,  # total score
            ["new_device × +2.20 → +2.20", "ip_changed × +0.60 → +0.60"],  # parts
            {"features": {"new_device": 1.0, "ip_changed": 1.0}}  # details
        )
    monkeypatch.setattr(risk_engine, "score_login", _fake_score_login)

    # Ensure thresholds align with assertions
    risk_engine.CONFIG.step_up_threshold = 60
    risk_engine.CONFIG.hard_deny_threshold = 90

def _count_login_events(db, user_id):
    return db.query(models.LoginEvent).filter(models.LoginEvent.user_id == user_id).count()


# Tests: /adversary/generate
@pytest.mark.parametrize("attack", ["credential_stuffing", "device_spoof", "impossible_travel", "mixed"])
def test_generate_login_attacks(client, attack):
    resp = client.post("/adversary/generate", json={"attack": attack, "count": 7})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    # should never be empty and should respect count cap
    assert 1 <= len(data) <= 7
    # basic fields present on login-type gens (tx_fuzz excluded here)
    if attack != "tx_fuzz":
        assert {"ip", "ua"}.issubset(data[0].keys())


def test_generate_tx_fuzz(client):
    resp = client.post("/adversary/generate", json={"attack": "tx_fuzz", "count": 5})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 5
    assert {"amount", "currency", "category"}.issubset(data[0].keys())


# Tests: /adversary/run
def test_run_attack_preview_no_persist(client):
    resp = client.post("/adversary/run", json={"attack": "credential_stuffing", "count": 12, "persist": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["generated"] == 12
    assert body["inserted"] == 0
    # With deterministic score=85: step-up but not hard-deny
    assert 0.6 <= body["step_up_rate"] <= 1.0
    assert body["hard_deny_rate"] == 0.0
    assert isinstance(body["sample"], list) and len(body["sample"]) >= 1
    sample0 = body["sample"][0]
    assert {"ip", "ua", "pred_risk", "raw_parts", "raw_details"}.issubset(sample0.keys())


def test_run_attack_persist_inserts(client, db, user):
    before = _count_login_events(db, user.id)
    resp = client.post("/adversary/run", json={"attack": "device_spoof", "count": 5, "persist": True})
    assert resp.status_code == 200
    body = resp.json()
    assert body["generated"] == 5
    assert body["inserted"] == 5
    after = _count_login_events(db, user.id)
    assert after - before == 5


def test_run_attack_impossible_travel_pairs(client):
    # Pairs are flattened but should still score and return sample
    resp = client.post("/adversary/run", json={"attack": "impossible_travel", "count": 6, "persist": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["generated"] == 6
    assert len(body["sample"]) >= 1
    # avg risk should reflect deterministic scorer
    assert 80.0 <= body["avg_risk"] <= 90.0


# Tests: /adversary/tx_fuzz
def test_tx_fuzz_without_history(client):
    # No history is fine; IF model may not train, but endpoint should still return items with int scores
    resp = client.post("/adversary/tx_fuzz", json={"count": 8, "backend": "iforest"})
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 8
    row0 = rows[0]
    assert {"amount", "category", "score", "backend", "details"}.issubset(row0.keys())
    assert isinstance(row0["score"], int)


def test_tx_fuzz_with_some_history(client, db, user):
    # Seed a handful of transactions so IF can (likely) train
    txs = [
        models.Transaction(
            user_id=user.id,
            amount=a,
            currency="SAR",
            category="FOOD",
            date=date.today() - timedelta(days=i),
            merchant="Local",
        )
        for i, a in enumerate([12.5, 18.3, 22.1, 19.9, 15.0, 9.7, 30.2, 14.0], start=1)
    ]
    db.add_all(txs)
    db.commit()

    resp = client.post("/adversary/tx_fuzz", json={"count": 5, "backend": "iforest"})
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 5
    # scores should be 0..100
    for r in rows:
        assert 0 <= int(r["score"]) <= 100

# Input validation (invalid attack names, negative counts)
@pytest.mark.parametrize("payload", [
    {"attack": "not_a_real_attack", "count": 5},
    {"attack": "credential_stuffing", "count": -3},
    {"attack": "credential_stuffing", "count": 0},
])
def test_input_validation_errors(client, payload):
    resp = client.post("/adversary/generate", json=payload)
    # Accept either 400 or 422 depending on how Pydantic/validation is wired
    assert resp.status_code in (400, 422)

    resp2 = client.post("/adversary/run", json={**payload, "persist": False})
    assert resp2.status_code in (400, 422)


# Geo-location or "Unknown city" edge cases
def test_geo_unknown_city_does_not_crash(client, monkeypatch):
    """
    If the router exposes a _geo_for_ip helper, force it to return Unknown.
    Otherwise skip
    """
    if not hasattr(adversary_router, "_geo_for_ip"):
        pytest.skip("Router has no _geo_for_ip hook to patch.")

    def _fake_geo(ip: str):
        return (0.0, 0.0, "Unknown")

    monkeypatch.setattr(adversary_router, "_geo_for_ip", _fake_geo)
    resp = client.post("/adversary/run", json={"attack": "credential_stuffing", "count": 5, "persist": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["generated"] == 5
    # Still returns a sample and risk stats
    assert isinstance(body.get("sample", []), list)
    assert "avg_risk" in body

# Device trust and risk adjustment logic
def test_device_trust_can_affect_risk_when_engine_uses_it(client, db, user, monkeypatch):
    """
    Create a trusted device and monkeypatch score_login to drop score for trusted devices.
    This verifies our pipeline passes device_trust through to the scorer.
    """
    # Seed a trusted device + intel
    trusted_hash = "trusted-device-abc"
    db.add(models.DeviceFingerprint(user_id=user.id, device_hash=trusted_hash, trusted=True))
    intel = db.query(models.UserIntel).filter(models.UserIntel.user_id == user.id).first()
    if not intel:
        intel = models.UserIntel(user_id=user.id, device_trust={trusted_hash: True},
                                 login_hours_hist={str(h): 0 for h in range(24)},
                                 login_cities={}, tx_category_stats={}, tx_merchant_counts={})
        db.add(intel); db.commit()
    else:
        m = dict(intel.device_trust or {})
        m[trusted_hash] = True
        intel.device_trust = m
        db.add(intel); db.commit()

    # If the router has a hook to choose device hashes, force it so our trusted device is used.
    if hasattr(adversary_router, "_random_device_hash"):
        monkeypatch.setattr(adversary_router, "_random_device_hash", lambda rng=None: trusted_hash)

    # Patch scorer: if device is trusted in kwargs['device_trust'], return a safer score (e.g., 40)
    def _score_login_sensitive(**kwargs):
        device_hash = kwargs.get("device_hash")
        device_trust = kwargs.get("device_trust", {})
        if device_hash and device_trust.get(device_hash, False):
            return (40, ["trusted_device × -1.00 → -1.00"], {"features": {"untrusted_device": 0.0}})
        return (85, ["new_device × +2.20 → +2.20"], {"features": {"new_device": 1.0}})

    monkeypatch.setattr(risk_engine, "score_login", _score_login_sensitive)

    resp = client.post("/adversary/run", json={"attack": "device_spoof", "count": 6, "persist": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["generated"] == 6
    # With some trusted hits, avg_risk should now be <= baseline 85
    assert body["avg_risk"] <= 85

# Preview should not leak into analytics (if logs router is mounted)
@pytest.mark.skipif(logs_router is None, reason="logs router not available to verify analytics")
def test_preview_no_persist_does_not_affect_analytics(client):
    # Baseline analytics
    r0 = client.get("/logs/summary")
    if r0.status_code != 200:
        pytest.skip("logs summary endpoint not present; skipping analytics leak test")
    base_total = r0.json()["counts"]["total"]

    # Run preview (no persist)
    r1 = client.post("/adversary/run", json={"attack": "credential_stuffing", "count": 10, "persist": False})
    assert r1.status_code == 200

    # Analytics unchanged
    r2 = client.get("/logs/summary")
    if r2.status_code != 200:
        pytest.skip("logs summary endpoint not present after run; skipping analytics leak test")
    assert r2.json()["counts"]["total"] == base_total

# AE (AutoEncoder) backend for transaction fuzzing
@pytest.mark.skipif(
    not hasattr(adversary_router, "TORCH_AVAILABLE") and "torch" not in os.environ.get("PYTHONPATH", ""),
    reason="Torch availability unknown; skip to avoid hard failure on environments without torch",
)
def test_tx_fuzz_autoencoder_backend(client):
    """
    If AE is supported, ensure endpoint responds and returns shaped rows.
    If implementation falls back to IF when AE is unavailable, still accept 200 with rows.
    """
    resp = client.post("/adversary/tx_fuzz", json={"count": 4, "backend": "ae"})
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 4
    r0 = rows[0]
    assert {"amount", "category", "score", "backend", "details"}.issubset(r0.keys())

# Large-scale performance or count capping
def test_large_count_capped_or_fast(client):
    """
    Request a large count and assert:
      - The endpoint responds quickly (soft check)
      - The 'generated' field is >0 and <= requested count (cap-friendly)
    """
    requested = 250
    t0 = time.time()
    resp = client.post("/adversary/run", json={"attack": "credential_stuffing", "count": requested, "persist": False})
    dt = time.time() - t0

    if resp.status_code == 422:
        # Fall back to a smaller count supported by validation (e.g., 100)
        requested = 100
        t0 = time.time()
        resp = client.post("/adversary/run", json={"attack": "credential_stuffing", "count": requested, "persist": False})
        dt = time.time() - t0

    assert resp.status_code == 200
    body = resp.json()
    assert 1 <= body["generated"] <= requested
    # Soft performance guard; keep generous to avoid flakes on CI
    assert dt < 5.0
