# tests/test_soc.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_alert_lifecycle():
    e = {"timestamp": 123, "ip": "1.1.1.1", "user": "bob", "event": "login_failed", "score": 88}
    r = client.post("/soc/alert", json=e)
    assert r.status_code == 200

    r = client.get("/soc/alerts")
    alerts = r.json()
    assert any(a["ip"] == "1.1.1.1" for a in alerts)

    r = client.get("/soc/recheck_ip", params={"ip": "1.1.1.1"})
    assert "ti_bad_ip" in r.json()
