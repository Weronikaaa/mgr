#!/usr/bin/env python3
import json
import os
from datetime import datetime

METRICS_DIR = "metrics"
OUTPUT_FILE = os.path.join(METRICS_DIR, "final_experiment_dataset.json")


def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, "r") as f:
        return json.load(f)


# =========================
# SAST DATA
# =========================
def build_sast():
    effectiveness = load_json(os.path.join(METRICS_DIR, "effectiveness-metrics.json"), {})

    return {
        "bandit": effectiveness.get("bandit", {}).get("metrics", {}),
        "semgrep": effectiveness.get("semgrep", {}).get("metrics", {}),
        "sonarqube": effectiveness.get("sonarqube", {}).get("metrics", {})
    }


# =========================
# SECRET SCANNING
# =========================
def build_secrets():
    gitleaks = load_json("gitleaks-report.json", {})
    trufflehog = load_json("trufflehog-report.json", {})

    def count_gitleaks(data):
        if isinstance(data, list):
            return len(data)
        return len(data.get("findings", []))

    def count_trufflehog(data):
        if isinstance(data, list):
            return len(data)
        return len(data.get("results", []))

    return {
        "gitleaks": {
            "secrets": count_gitleaks(gitleaks)
        },
        "trufflehog": {
            "secrets": count_trufflehog(trufflehog)
        }
    }


# =========================
# SCA + CONTAINERS
# =========================
def build_sca():
    trivy_fs = load_json("trivy-report.json", {})
    grype = load_json("grype-report.json", {})

    def count_trivy(data):
        total = 0
        for r in data.get("Results", []):
            total += len(r.get("Vulnerabilities", []) or [])
        return total

    def count_grype(data):
        return len(data.get("matches", []))

    return {
        "trivy_fs": {
            "vulnerabilities": count_trivy(trivy_fs)
        },
        "grype": {
            "vulnerabilities": count_grype(grype)
        }
    }


# =========================
# PIPELINE PERFORMANCE
# =========================
def build_pipeline_metrics():
    def get_env_float(name):
        try:
            return float(os.getenv(name, 0))
        except:
            return 0

    build_start = get_env_float("BUILD_START")
    build_end = get_env_float("BUILD_END")

    deploy_start = get_env_float("DEPLOY_START")
    deploy_end = get_env_float("DEPLOY_END")

    build_time = max(build_end - build_start, 0)
    deploy_time = max(deploy_end - deploy_start, 0)

    return {
        "build_sec": round(build_time, 2),
        "deploy_sec": round(deploy_time, 2),
        "total_sec": round(build_time + deploy_time, 2)
    }


# =========================
# MAIN
# =========================
def main():

    dataset = {
        "metadata": {
            "project": "DevSecOps CI/CD Security Evaluation",
            "generated_at": datetime.utcnow().isoformat()
        },

        "sast": build_sast(),
        "secret_scanning": build_secrets(),
        "sca": build_sca(),
        "pipeline_performance": build_pipeline_metrics()
    }

    os.makedirs(METRICS_DIR, exist_ok=True)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(dataset, f, indent=2)

    print("✅ FINAL DATASET GENERATED")
    print(f"📦 Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
