#!/usr/bin/env python3
import json
import os
from datetime import datetime

OUTPUT_FILE = "final_experiment_dataset.json"
GROUND_TRUTH_FILE = "ground_truth.json"


# =========================
# LOAD JSON
# =========================
def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


# =========================
# DETECTION FUNCTION (mapping rules)
# =========================
RULES = {
    "V01": ["sql", "execute", "sqlite"],
    "V02": ["subprocess", "shell=True", "command injection"],
    "V03": ["eval"],
    "V04": ["pickle"],
    "V05": ["md5"],
    "V06": ["path traversal", "open("],
    "V07": ["xss", "html"],
    "V08": ["redirect"],
    "V09": ["auth", "authorization"],
    "V10": ["upload"],
    "V11": ["os.environ", "environment"],
    "V12": ["token", "debug", "hash"]
}


def normalize(text):
    return str(text).lower()


def detect_vulnerabilities(text):
    text = normalize(text)
    detected = set()

    for vuln_id, patterns in RULES.items():
        for p in patterns:
            if p in text:
                detected.add(vuln_id)
                break

    return detected


# =========================
# PARSERS (RAW REPORTS ONLY)
# =========================

def parse_bandit():
    data = load_json("bandit-report.json")
    findings = set()

    for issue in data.get("results", []):
        text = (
            issue.get("issue_text", "") +
            issue.get("test_name", "") +
            issue.get("test_id", "")
        )
        findings |= detect_vulnerabilities(text)

    return findings


def parse_semgrep():
    data = load_json("semgrep-report.json")
    findings = set()

    for issue in data.get("results", []):
        text = (
            issue.get("check_id", "") +
            issue.get("extra", {}).get("message", "")
        )
        findings |= detect_vulnerabilities(text)

    return findings


def parse_sonarqube():
    data = load_json("sonarqube-metrics.json")
    return detect_vulnerabilities(str(data))


# =========================
# METRICS CALCULATION
# =========================
def calculate_metrics(detected, ground_truth):
    gt_set = set(ground_truth.keys())

    tp = len(detected & gt_set)
    fp = len(detected - gt_set)
    fn = len(gt_set - detected)

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / len(gt_set) if gt_set else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "detected": sorted(list(detected))
    }


# =========================
# MAIN
# =========================
def main():

    ground_truth = load_json(GROUND_TRUTH_FILE)

    tools = {
        "bandit": parse_bandit,
        "semgrep": parse_semgrep,
        "sonarqube": parse_sonarqube
    }

    results = {
        "metadata": {
            "project": "DevSecOps CI/CD Security Evaluation",
            "generated_at": datetime.now().isoformat()
        },
        "ground_truth": {
            "total_vulnerabilities": len(ground_truth),
            "items": list(ground_truth.keys())
        },
        "sast": {}
    }

    for tool_name, parser in tools.items():
        detected = parser()
        results["sast"][tool_name] = calculate_metrics(detected, ground_truth)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    print("✅ FINAL DATASET GENERATED (clean evaluation)")
    print(f"📁 {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
