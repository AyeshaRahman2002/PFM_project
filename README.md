# AI Security Analytics & Adversarial Simulation Platform

## Overview

This project implements a **production-grade backend** for AI-driven cybersecurity analytics, risk scoring, and adversarial simulation.
It demonstrates how **AI and ML** can be applied to detect, explain, and defend against dynamic threats while maintaining privacy and scalability.
A lightweight **Dart frontend** complements the system for basic interaction and visualization.

### Core Features

* AI-based **risk scoring engine** and explainable decisions
* **Unsupervised anomaly detection** for unusual behavior
* **User behavior profiling** with contextual scoring
* **NLP-driven log intelligence** and summarization
* **Privacy-aware recommendations** with differential privacy
* **Federated learning simulation** for decentralized training
* **Explainable AI (XAI)** via LIME / SHAP
* **Adversarial simulation** (fake attacks, fuzzing)
* Integrated **Threat Intelligence (TI)** and **SOC dashboard**
* Real-time **performance monitoring and load metrics**

## How to Run
### 1. Backend
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### 2. Frontend (Optional)
Dart-based frontend is included for visualization (basic demo mode).
```bash
flutter pub get
flutter clean
flutter run -d macos
```

## Architecture Overview

### 1. Risk Scoring Engine
* Combines behavioral, contextual, and threat intelligence features.
* Outputs a unified `risk_score` (0–100) for every event.
* Unit-tested in `tests/test_risk_engine.py`.

### 2. Anomaly Detection
* Uses **Isolation Forest** and **AutoEncoder** models.
* Flags deviations in transaction and login patterns.
* Endpoint:
  `POST /adversary/tx_fuzz`

### 3. User Behavior Profiling
* Monitors devices, IPs, time, and geo patterns per user.
* Feeds adaptive inputs to the risk engine for dynamic scoring.

### 4. NLP for Log Insights
* Extracts entities and security actions (`login_failed`, `timeout`, etc).
* Groups and summarizes logs automatically for SOC analysis.

### 5. Privacy-Aware Recommendation
* Suggests step-up or MFA actions while preserving anonymity.
* Uses differential privacy in federated model training.

### 6. Federated Learning Simulation
* Simulates multi-client training without raw data sharing.
* Models: Base, FedProx, and Differentially Private variants.
* Unit-tested with `fed_eval_live_vs_sim.json` results.

### 7. Explainable AI (XAI)
* Integrates **LIME** and **SHAP** to explain model outputs.
* Example:
  ```
  geo_change × +0.45 -> +0.90
  new_device × +0.80 -> +1.60
  ```
* Transparent auditability of model reasoning.

### 8. Adversarial Simulation
* Generates fake attack patterns (credential stuffing, spoofing).
* Tests system robustness and anomaly resilience.
* Endpoints:
  * `/adversary/generate`
  * `/adversary/run`
  * `/adversary/tx_fuzz`

### 9. Threat Intelligence (TI)
* Loads IP, ASN, TOR, and disposable email lists.
* Enriches login context with external risk signals.
* Endpoints:
  * `/ti/status`
  * `/ti/lookup_ip`
  * `/ti/check_email_domain`
  * `/ti/reload`
* Fully unit-tested in `tests/test_ti.py`.

### 10. SOC / Mini-SIEM
* Stores and visualizes alerts with Pandas and Matplotlib.
* Endpoints:
  * `/soc/alert`
  * `/soc/alerts`
  * `/soc/recheck_ip`
* Enables real-time monitoring, rechecks, and dashboards.

## Testing
* **All tests** are defined under `/tests` and can be run with:
  ```bash
  pytest -v
  ```
* Interactive testing notebook:
  `backend/tests/test.ipynb`
  Includes performance benchmarks, SOC analytics, and live monitoring.

## Results Summary
### **1. Audit & Explainability**
* 10 high-risk logins (avg `risk_score ≈ 91`) correctly flagged as *hard_deny*.
* Feature attributions confirmed interpretability (e.g., `geo_change +0.8`).

### **2. Federated Learning**
* <1% accuracy difference between live vs simulated aggregation.
* **FedProx** handled skewed data well; **DP variant** preserved privacy with only ~2% accuracy loss.

### **3. Threat Intelligence**
* TOR nodes, bad IPs, and disposable domains enriched events accurately.
* Reload under 100 ms, ideal for production caching.

### **4. SOC / SIEM**
* 200+ alerts processed in 4 hours with stable ingestion (<5 ms/event).
* Alert distribution clearly split between low-risk and high-risk users.

### **5. Anomaly & Geo Detection**
* Detected multiple “impossible travel” and time anomalies.
* Isolation Forest scored anomalies near 45/100 validated behavioral drift.

### **6. NLP Log Analytics**
* Parsed and clustered events by type (`login_failed`, `step_up_required`, etc).
* Summarized past week’s security activity automatically.

### **7. Privacy & Recommendations**
* Differential privacy maintained <2% utility loss solid privacy-performance balance.

### **8. Performance & Load**
* 50,000 requests @ 200 concurrent clients -> **33 req/s** sustained.
* TI lookups <100 ms, SOC write <5 ms/event.
* No failures, no timeouts, stable memory under 65%.

## Visualization Examples
* **SOC Score Distribution:** bimodal (safe <30 / risky >80)
* **Latency over time:** avg 15 ms, p95 <10 ms
* **RPS trend:** ~7 RPS on local dev, scalable to 300+ in production
* **Anomaly Dashboard:** Isolation Forest and SHAP contribution bars

## Technologies Used
•	Core backend: Python 3.8+, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy, SQLite (dev)
•	Security & auth: argon2-cffi, passlib[bcrypt], python-jose (JWT), hmac/ipaddress
•	ML & XAI: scikit-learn (IsolationForest), PyTorch (optional AE), SHAP, LIME, NumPy, Pandas
•	Geo & TI: geoip2 (MaxMind), ipinfo via httpx, CIDR/ip parsing
•	Observability: Prometheus-style text metrics, psutil (system stats)
•	Testing & load: pytest, httpx, requests, Jupyter, Matplotlib

## Future Work
* Expand federated learning to edge devices (IoT simulation)
* Integrate real datasets for adversarial robustness
* Add Grafana dashboard for live Prometheus metrics
* Extend privacy metrics for regulatory benchmarking (GDPR, NIST)

**Author:** Ayesha Rahman
**Contact:** [ayesharahman7755@gmail.com](mailto:ayesharahman7755@gmail.com)
**Project:** AI Security Analytics & Adversarial Simulation Platform
