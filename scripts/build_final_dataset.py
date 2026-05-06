#!/usr/bin/env python3
import json
import os
from datetime import datetime

OUTPUT_FILE = "final_experiment_dataset.json"


def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def main():

    dataset = {
        "metadata": {
            "project": "DevSecOps CI/CD Security Evaluation",
            "generated_at": datetime.now().isoformat()
        },
       
        "ground_truth": {
            "total_vulnerabilities": 23
        },

        "pipeline_breakdown": {
            "build": load_json("metrics/build.json").get("duration_sec", 0),
            "sast": load_json("metrics/sast_total.json").get("duration_sec", 0),
            "deploy": load_json("metrics/deploy.json").get("duration_sec", 0),
            "secret_scanning": load_json("metrics/secrets.json").get("duration_sec", 0),
            "sca": load_json("metrics/sca.json").get("duration_sec", 0)
        },
        
        # =========================
        # EFFECTIVENESS (TP/FP/FN)
        # =========================
        "effectiveness": load_json("metrics/effectiveness-metrics.json"),

        # =========================
        # RAW TOOL RESULTS (optional full traceability)
        # =========================
        "raw_reports": {
            "bandit": load_json("bandit-report.json"),
            "semgrep": load_json("semgrep-report.json"),
            "sonarqube": load_json("sonarqube-metrics.json"),
            "gitleaks": load_json("gitleaks-report.json"),
            "trufflehog": load_json("trufflehog-report.json"),
            "trivy_fs": load_json("trivy-report.json"),
            "trivy_image": load_json("trivy-image.json"),
            "grype": load_json("grype-report.json")
        },

        # =========================
        # PIPELINE PERFORMANCE
        # =========================
        "pipeline_performance": load_json("metrics/tool-metrics.json"),

        # =========================
        # AGGREGATED RESULTS
        # =========================
        "aggregated": load_json("metrics/comparison-metrics.json")
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(dataset, f, indent=2)

    print("✅ FINAL DATASET GENERATED")
    print(f"📁 File: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
