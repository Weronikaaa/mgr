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

CWE_MAP = {
    "CWE-798": "V01",
    "CWE-89": "V02",
    "CWE-78": "V03",
    "CWE-94": "V04",
    "CWE-502": "V05",
    "CWE-327": "V06",
    "CWE-22": "V07",
    "CWE-79": "V08",
    "CWE-601": "V09",
    "CWE-284": "V10",
    "CWE-434": "V11",
    "CWE-200": "V12",
    "CWE-330": "V13",
    "CWE-489": "V14",
    "CWE-1104": "V15",
    "CWE-250": "V18",
    "CWE-693": "V19",
    "CWE-494": "V20",
    "CWE-1008": "V21",
    "CWE-16": "V23"
}
def extract_cwes(text):
    text = str(text).lower()
    detected = set()

    for cwe, vuln_id in CWE_MAP.items():

        cwe_id = cwe.lower().split(":")[0]   # 🔥 FIX

        if cwe_id in text:
            detected.add(vuln_id)

    return detected

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
            issue.get("test_name", ""),
            issue.get("test_id", ""),
            str(issue.get("issue_cwe", ""))
        ])

        findings |= extract_cwes(text)

    return findings


def parse_semgrep():
    data = load_json("semgrep-report.json")
    findings = set()

    for issue in data.get("results", []):

        cwe_list = issue.get("extra", {}).get("metadata", {}).get("cwe", [])

        text = issue.get("check_id", "")

        # 🔥 dodaj CWE bezpośrednio
        text += " " + " ".join(cwe_list)

        findings |= extract_cwes(text)

    return findings


def parse_sonarqube():
    data = load_json("sonarqube-metrics.json")

    text = ""

    for m in data.get("component", {}).get("measures", []):
        text += str(m.get("metric", "")) + " " + str(m.get("value", ""))

    return extract_cwes(text)


# =========================
# METRICS
# =========================
def calculate_metrics(detected, ground_truth):
    gt = set(ground_truth.keys())

    tp = len(detected & gt)
    fp = len(detected - gt)
    fn = len(gt - detected)

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / len(gt) if gt else 0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0

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

    detected = parse_semgrep()
print("SEMgrep detected:", detected)

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
