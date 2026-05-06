#!/usr/bin/env python3
import json
import os
from datetime import datetime

OUTPUT_FILE = "final_experiment_dataset.json"
GROUND_TRUTH_FILE = "data/ground_truth.json"


# =========================
# LOAD JSON
# =========================
def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


# =========================
# IMPROVED RULE-BASED MAPPING (ACADEMIC VERSION)
# =========================
RULES = {
    "V01": ["hardcoded", "secret", "api key", "password"],
    "V02": ["sql", "sql injection", "cwe-89", "execute", "sqlite"],
    "V03": ["command injection", "subprocess", "cwe-78", "shell=true"],
    "V04": ["eval", "code injection", "cwe-94"],
    "V05": ["pickle", "deserialization", "cwe-502"],
    "V06": ["md5", "weak hash", "cwe-327"],
    "V07": ["path traversal", "cwe-22", "open("],
    "V08": ["xss", "cross-site scripting", "html"],
    "V09": ["redirect", "open redirect", "cwe-601"],
    "V10": ["access control", "authorization", "broken access"],
    "V11": ["upload", "file upload", "cwe-434"],
    "V12": ["information disclosure", "debug", "os.environ", "cwe-200"],
    "V13": ["token", "predictable", "random", "hash"],
    "V14": ["debug mode", "flask debug", "cwe-489"]
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
# PARSERS (RAW REPORTS)
# =========================

def parse_bandit():
    data = load_json("bandit-report.json")
    findings = set()

    for issue in data.get("results", []):
        text = " ".join([
            issue.get("issue_text", ""),
            issue.get("test_name", ""),
            issue.get("test_id", "")
        ])
        findings |= detect_vulnerabilities(text)

    return findings


def parse_semgrep():
    data = load_json("semgrep-report.json")
    findings = set()

    for issue in data.get("results", []):
        text = " ".join([
            issue.get("check_id", ""),
            issue.get("extra", {}).get("message", "")
        ])
        findings |= detect_vulnerabilities(text)

    return findings


def parse_sonarqube():
    data = load_json("sonarqube-metrics.json")

    findings = set()

    measures = data.get("component", {}).get("measures", [])

    for m in measures:
        text = m.get("metric", "")
        findings |= detect_vulnerabilities(text)

    return findings


# =========================
# METRICS
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

    ground_truth_raw = load_json(GROUND_TRUTH_FILE)
    ground_truth = ground_truth_raw.get("vulnerabilities", {})

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

    print("✅ FINAL DATASET GENERATED")
    print(f"📁 {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
