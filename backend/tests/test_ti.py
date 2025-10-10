# tests/test_ti.py
import importlib
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app import threat_intel as ti
from app.deps import current_user

# Make every test authenticated by default
@pytest.fixture(autouse=True)
def _override_auth_dependency():
    from types import SimpleNamespace
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(id=1, email="ti@test.local")
    yield
    app.dependency_overrides.pop(current_user, None)


@pytest.fixture
def ti_env(tmp_path, monkeypatch):
    # Preparing temporary TI feeds, reload app.threat_intel, and hydrate state.
    bad_ip_file = tmp_path / "bad_ips.txt"
    bad_ip_file.write_text("1.1.1.1\n192.0.2.0/24\n")

    tor_file = tmp_path / "tor_ips.txt"
    tor_file.write_text("2.2.2.2\n")

    bad_asn_file = tmp_path / "bad_asn.txt"
    bad_asn_file.write_text("AS64512\n")

    monkeypatch.setenv("TI_ENABLE", "1")
    monkeypatch.setenv("TI_IP_REPUTATION_PATH", str(bad_ip_file))
    monkeypatch.setenv("TI_TOR_LIST_PATH", str(tor_file))
    monkeypatch.setenv("TI_BAD_ASN_PATH", str(bad_asn_file))
    monkeypatch.setenv("TI_BAD_EMAIL_DOMAINS", "mailinator.com, temp-mail.org")

    import app.threat_intel as ti_mod
    importlib.reload(ti_mod)

    # Ensure the FastAPI router uses the reloaded module
    from app import main as app_main
    app_main.threat_intel = ti_mod

    ti_mod.reload()
    yield ti_mod

def test_status_counts(ti_env):
    client = TestClient(app)
    r = client.get("/ti/status")
    assert r.status_code == 200
    js = r.json()
    assert js["enabled"] is True
    assert js["counts"]["bad_ip"] == 2
    assert js["counts"]["tor"] == 1
    assert js["counts"]["bad_asn"] == 1
    assert js["counts"]["bad_domains"] == 2

def test_lookup_bad_ip(ti_env):
    client = TestClient(app)
    r = client.get("/ti/lookup_ip", params={"ip": "1.1.1.1"})
    assert r.status_code == 200
    js = r.json()
    assert js["ti_bad_ip"] is True
    assert js["ti_tor_exit"] is False

def test_lookup_tor_ip(ti_env):
    client = TestClient(app)
    r = client.get("/ti/lookup_ip", params={"ip": "2.2.2.2"})
    assert r.status_code == 200
    js = r.json()
    assert js["ti_tor_exit"] is True
    assert js["ti_bad_ip"] is False

def test_check_email_domain_disposable(ti_env):
    client = TestClient(app)
    r = client.get("/ti/check_email_domain", params={"email": "alice@mailinator.com"})
    assert r.status_code == 200
    js = r.json()
    assert js["domain"] == "mailinator.com"
    assert js["ti_disposable_email"] is True

def test_ti_disabled(monkeypatch):
    """
    When TI is disabled, status should reflect empty counts.
    """
    monkeypatch.setenv("TI_ENABLE", "0")
    import app.threat_intel as ti_mod
    importlib.reload(ti_mod)

    from app import main as app_main
    app_main.threat_intel = ti_mod

    client = TestClient(app)
    r = client.get("/ti/status")
    assert r.status_code == 200
    js = r.json()
    assert js["enabled"] is False
    assert js["counts"]["bad_ip"] == 0
    assert js["counts"]["tor"] == 0
    assert js["counts"]["bad_asn"] == 0