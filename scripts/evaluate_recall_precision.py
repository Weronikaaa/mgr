#!/usr/bin/env python3

import json
import os
from pathlib import Path
from datetime import datetime


GROUND_TRUTH_FILE = "vulnerabilities_ground_truth.json"
OUTPUT_DIR = "metrics"

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ===================================
# GROUND TRUTH
# ===================================

with open(GROUND_TRUTH_FILE) as f:
    ground_truth = json.load(f)

ALL_VULNS = set(ground_truth.keys())


# ===================================
# DETECTION RULES
# ===================================

RULES = {
    "V1": ["sql", "sqlite", "execute"],
    "V2": ["subprocess", "shell=true", "command injection"],
    "V3": ["eval"],
    "V4": ["pickle"],
    "V5": ["md5"],
    "V6": ["path traversal", "open("],
    "V7": ["xss", "html"],
    "V8": ["redirect"],
    "V9": ["auth", "authorization"],
    "V10": ["upload"],
    "V11": ["environment", "os.environ"],
    "V12": ["random", "hash"]
}


# ===================================
# HELPERS
# ===================================

def normalize(text):
    return str(text).lower()


def detect_vulnerabilities(text):
    detected = set()

    text = normalize(text)

    for vuln_id, patterns in RULES.items():

        for pattern in patterns:

            if pattern in text:
                detected.add(vuln_id)
                break

    return detected


# ===================================
# PARSERS
# ===================================

def parse_bandit():

    if not os.path.exists("bandit-report.json"):
        return set()

    with open("bandit-report.json") as f:
        data = json.load(f)

    findings = set()

    for issue in data.get("results", []):

        text = (
            issue.get("issue_text", "")
            + issue.get("test_name", "")
            + issue.get("test_id", "")
        )

        findings |= detect_vulnerabilities(text)

    return findings


def parse_semgrep():

    if not os.path.exists("semgrep-report.json"):
        return set()

    with open("semgrep-report.json") as f:
        data = json.load(f)

    findings = set()

    for issue in data.get("results", []):

        extra = issue.get("extra", {})
        metadata = extra.get("metadata", {})

        text = (
            issue.get("check_id", "")
            + extra.get("message", "")
            + str(metadata.get("cwe", []))
            + str(metadata.get("owasp", []))
        )

        findings |= detect_vulnerabilities(text)

    return findings


def parse_sonarqube():

    if not os.path.exists("sonarqube-metrics.json"):
        return set()

    with open("sonarqube-metrics.json") as f:
        data = json.load(f)

    findings = detect_vulnerabilities(str(data))

    return findings


# ===================================
# METRICS
# ===================================

def calculate_metrics(detected):

    tp = len(detected)

    fn = len(ALL_VULNS - detected)

    fp = 0

    precision = tp / (tp + fp) if (tp + fp) else 0

    recall = tp / len(ALL_VULNS)

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0
    )

    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "detected_vulnerabilities": sorted(list(detected))
    }


# ===================================
# MAIN
# ===================================

def main():

    results = {}

    tools = {
        "bandit": parse_bandit,
        "semgrep": parse_semgrep,
        "sonarqube": parse_sonarqube
    }

    for tool, parser in tools.items():

        detected = parser()

        results[tool] = {
            "timestamp": datetime.now().isoformat(),
            "metrics": calculate_metrics(detected)
        }

    output_file = f"{OUTPUT_DIR}/effectiveness-metrics.json"

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print("✅ Effectiveness metrics saved")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
