import json
import os
import time
from datetime import datetime

METRICS_DIR = "metrics"
os.makedirs(METRICS_DIR, exist_ok=True)


def save_json(name, data):
    path = f"{METRICS_DIR}/{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# =========================
# BUILD METRICS
# =========================
def collect_build_metrics():
    start = float(os.getenv("BUILD_START", 0))
    end = float(os.getenv("BUILD_END", time.time()))

    return {
        "stage": "build",
        "duration_sec": round(end - start, 2),
        "timestamp": datetime.utcnow().isoformat()
    }


# =========================
# SAST METRICS (example: Sonar/Trivy JSON)
# =========================
def collect_sast_metrics():
    try:
        with open("trivy-python.json") as f:
            data = json.load(f)

        vulns = sum(
            len(result.get("Vulnerabilities", []) or [])
            for result in data.get("Results", [])
        )

    except FileNotFoundError:
        vulns = 0

    return {
        "stage": "sast",
        "vulnerabilities": vulns,
        "tool": "trivy",
        "timestamp": datetime.utcnow().isoformat()
    }


# =========================
# SCA METRICS
# =========================
def collect_sca_metrics():
    try:
        with open("trivy-python.json") as f:
            data = json.load(f)

        critical = 0
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []) or []:
                if v.get("Severity") == "CRITICAL":
                    critical += 1

    except FileNotFoundError:
        critical = 0

    return {
        "stage": "sca",
        "critical_vulnerabilities": critical,
        "tool": "trivy",
        "timestamp": datetime.utcnow().isoformat()
    }


# =========================
# DEPLOY METRICS
# =========================
def collect_deploy_metrics():
    start = float(os.getenv("DEPLOY_START", 0))
    end = float(os.getenv("DEPLOY_END", time.time()))

    return {
        "stage": "deploy",
        "duration_sec": round(end - start, 2),
        "timestamp": datetime.utcnow().isoformat()
    }


# =========================
# SMOKE TEST METRICS
# =========================
def collect_smoke_metrics():
    try:
        with open("smoke-test-results.json") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {"status": "unknown"}

    return {
        "stage": "smoke",
        "status": data.get("status", "unknown"),
        "timestamp": datetime.utcnow().isoformat()
    }


# =========================
# MAIN PIPELINE
# =========================
if __name__ == "__main__":

    metrics = [
        collect_build_metrics(),
        collect_sast_metrics(),
        collect_sca_metrics(),
        collect_deploy_metrics(),
        collect_smoke_metrics()
    ]

    save_json("pipeline_metrics", metrics)

    print("✅ Metrics collected:")
    for m in metrics:
        print(m)
