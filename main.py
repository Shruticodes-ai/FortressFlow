import numpy as np
import xgboost as xgb
import shap
import time
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Dict

app = FastAPI(title="FortressFlow Hybrid Threat Gateway")
templates = Jinja2Templates(directory="templates")

# Initialize XGBoost Model & SHAP Explainer
X_train = np.random.rand(200, 5)
y_train = np.random.randint(0, 2, size=200)
model = xgb.XGBClassifier(n_estimators=15, max_depth=3, eval_metric="logloss")
model.fit(X_train, y_train)

explainer = shap.Explainer(model)
FEATURE_NAMES = ["Avg Packet Length", "Payload Entropy", "TCP Flag Ratio", "Flow Duration", "Port Risk"]

QUARANTINE_REGISTRY: Dict[str, Dict] = {}

class StreamRequest(BaseModel):
    source_ip: str
    destination_port: int
    packet_length_avg: float
    byte_entropy: float
    tcp_flags_ratio: float
    flow_duration_ms: float
    scan_mode: str  # "AUTOMATIC" or "MANUAL"

class ClearanceRequest(BaseModel):
    source_ip: str
    operator_reason: str

def process_threat_analysis(data: StreamRequest):
    # 1. Rule Engine Heuristics
    heuristic_score = 0
    alerts = []
    if data.byte_entropy > 7.0:
        heuristic_score += 40
        alerts.append("CRITICAL: High Payload Entropy (>7.0)")
    if data.destination_port in [4444, 5555, 6667, 31337]:
        heuristic_score += 35
        alerts.append(f"WARNING: Suspicious Port {data.destination_port}")
    if data.tcp_flags_ratio > 0.8:
        heuristic_score += 25
        alerts.append("ALERT: Anomalous TCP Flag Combination")

    # 2. ML Inference
    port_risk = 1.0 if data.destination_port in [4444, 5555, 6667, 31337] else 0.1
    features = np.array([[
        data.packet_length_avg / 1500.0,
        data.byte_entropy / 8.0,
        data.tcp_flags_ratio,
        min(data.flow_duration_ms / 10000.0, 1.0),
        port_risk
    ]])
    
    ml_prob = float(model.predict_proba(features)[0][1])
    final_risk = max(heuristic_score, int(ml_prob * 100))
    status = "MALICIOUS" if final_risk >= 60 else "BENIGN"

    # 3. SHAP Feature Attribution
    shap_vals = explainer(features).values[0]
    shap_xai = {name: round(float(v), 4) for name, v in zip(FEATURE_NAMES, shap_vals)}

    # 4. Remediation Decision
    if final_risk >= 80:
        action = "AUTO_NULL_ROUTE" if data.scan_mode == "AUTOMATIC" else "QUARANTINE_RECOMMENDED"
        details = f"Threat Isolated: Traffic from {data.source_ip}:{data.destination_port} blocked."
        QUARANTINE_REGISTRY[data.source_ip] = {
            "status": "ISOLATED",
            "risk_score": final_risk,
            "port": data.destination_port,
            "timestamp": time.strftime("%H:%M:%S IST")
        }
    elif final_risk >= 60:
        action = "AUTO_PAYLOAD_STRIP" if data.scan_mode == "AUTOMATIC" else "FLAGGED_FOR_INSPECTION"
        details = "Payload stripped at ingress diode queue."
    else:
        action = "PASSED"
        details = "Stream verified benign. Forwarded downstream."

    return {
        "source_ip": data.source_ip,
        "destination_port": data.destination_port,
        "scan_mode": data.scan_mode,
        "threat_status": status,
        "overall_risk_score": final_risk,
        "heuristics": {"score": heuristic_score, "alerts": alerts},
        "ml_probability": round(ml_prob, 4),
        "shap_xai_attribution": shap_xai,
        "action_taken": action,
        "details": details,
        "timestamp": time.strftime("%H:%M:%S IST")
    }

@app.post("/api/v1/scan")
async def scan_endpoint(data: StreamRequest):
    return process_threat_analysis(data)

@app.post("/api/v1/clear-threat")
async def clear_threat(req: ClearanceRequest):
    if req.source_ip in QUARANTINE_REGISTRY:
        del QUARANTINE_REGISTRY[req.source_ip]
        return {
            "status": "SUCCESS",
            "message": f"IP {req.source_ip} manually cleared and unblocked.",
            "operator_reason": req.operator_reason,
            "timestamp": time.strftime("%H:%M:%S IST")
        }
    return {"status": "NOT_FOUND", "message": "IP not found in active quarantine list."}

@app.get("/api/v1/quarantine-list")
async def get_quarantine():
    return QUARANTINE_REGISTRY

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})