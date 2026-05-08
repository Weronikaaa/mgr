#!/usr/bin/env python3

import json
import os
import csv
from datetime import datetime

GROUND_TRUTH_FILE = "data/ground_truth.json"

# =========================================

# LOAD JSON

# =========================================

def load_json(path):

    if not os.path.exists(path):
        return {}

    with open(path, "r") as f:
        return json.load(f)


# =========================================

# LOAD GROUND TRUTH

# =========================================

ground_truth_raw = load_json(GROUND_TRUTH_FILE)

GROUND_TRUTH = ground_truth_raw.get("vulnerabilities", {})

GT_BY_CATEGORY = {}

for vuln_id, vuln in GROUND_TRUTH.items():

    category = vuln["category"]

    if category not in GT_BY_CATEGORY:
        GT_BY_CATEGORY[category] = set()

    GT_BY_CATEGORY[category].add(vuln_id)


# =========================================

# CWE -> VULN MAP

# =========================================

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
"CWE-250": "V17",
"CWE-693": "V18",
"CWE-494": "V19",
"CWE-16": "V20",
"CWE-306": "V21"
}

# =========================================

# HELPERS

# =========================================

def extract_cwes(text):

    text = str(text).upper().replace(":", "-")

    detected = set()

    for cwe, vuln_id in CWE_MAP.items():

        normalized = cwe.upper()

        short = normalized.replace("CWE-", "")

        if normalized in text or short in text:
            detected.add(vuln_id)

    return detected


def calculate_metrics(detected, expected):

    tp = len(detected & expected)

    fp = len(detected - expected)

    fn = len(expected - detected)

    precision = tp / (tp + fp) if (tp + fp) else 0

    recall = tp / (tp + fn) if (tp + fn) else 0

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
        "detected": sorted(list(detected))
    }


# =========================================

# BANDIT

# =========================================

def parse_bandit():

    path = "bandit-report.json"

    if not os.path.exists(path):
        return set()

    data = load_json(path)

    findings = set()

    for issue in data.get("results", []):

        text = (
            str(issue.get("issue_cwe", ""))
            + issue.get("issue_text", "")
            + issue.get("test_name", "")
        )

        findings |= extract_cwes(text)

    return findings


# =========================================

# SEMGREP

# =========================================

def parse_semgrep():

    path = "semgrep-report.json"

    if not os.path.exists(path):
        return set()

    data = load_json(path)

    findings = set()

    for issue in data.get("results", []):

        metadata = issue.get("extra", {}).get("metadata", {})

        cwe = metadata.get("cwe", [])

        text = (
            issue.get("check_id", "")
            + issue.get("extra", {}).get("message", "")
            + str(cwe)
        )

        findings |= extract_cwes(text)

    return findings


# =========================================

# GITLEAKS

# =========================================

def parse_gitleaks():

    path = "gitleaks-report.json"

    if not os.path.exists(path):
        return set()

    data = load_json(path)

    if isinstance(data, list) and len(data) > 0:
        return {"V01"}

    return set()


# =========================================

# TRUFFLEHOG

# =========================================

def parse_trufflehog():

    path = "trufflehog-report.json"

    if not os.path.exists(path):
        return set()

    findings = []

    with open(path, "r") as f:

        for line in f.readlines():

            try:
                findings.append(json.loads(line))
            except:
                pass

    if len(findings) > 0:
        return {"V01"}

    return set()


# =========================================

# TRIVY FS

# =========================================

def parse_trivy_fs():

    path = "trivy-report.json"

    if not os.path.exists(path):
        return set()

    data = load_json(path)

    findings = set()

    for result in data.get("Results", []):

        for vuln in result.get("Vulnerabilities", []):

            pkg = vuln.get("PkgName", "").lower()

            if pkg == "flask":
                findings.add("V15")

            if pkg == "requests":
                findings.add("V16")

    return findings


# =========================================

# GRYPE

# =========================================

def parse_grype():

    path = "grype-report.json"

    if not os.path.exists(path):
        return set()

    data = load_json(path)

    findings = set()

    for match in data.get("matches", []):

        artifact = match.get("artifact", {})
        name = artifact.get("name", "").lower()

        if name == "flask":
            findings.add("V15")

        if name == "requests":
            findings.add("V16")

        if "python" in name:
            findings.add("V18")

    return findings
    
# =========================================

# ZAP

# =========================================

def parse_zap():

    path = "zap-report.json"

    if not os.path.exists(path):
        return set()

    data = load_json(path)

    raw = json.dumps(data).lower()

    findings = set()

    if "cross site scripting" in raw or "xss" in raw:
        findings.add("V22")

    if "redirect" in raw:
        findings.add("V23")

    if "authentication" in raw or "absence of anti-csrf" in raw:
        findings.add("V21")

    return findings


# =========================================

# TOOL DEFINITIONS

# =========================================

TOOLS = {
"bandit": {
"parser": parse_bandit,
"category": "SAST"
},


"semgrep": {
    "parser": parse_semgrep,
    "category": "SAST"
},

"gitleaks": {
    "parser": parse_gitleaks,
    "category": "Secrets"
},

"trufflehog": {
    "parser": parse_trufflehog,
    "category": "Secrets"
},

"trivy_fs": {
    "parser": parse_trivy_fs,
    "category": "SCA"
},

"grype": {
    "parser": parse_grype,
    "category": "SCA_CONTAINER",
    "expected": {"V15", "V16", "V17", "V18", "V19", "V20"}
},

"zap": {
    "parser": parse_zap,
    "category": "DAST"
}


}

# =========================================

# MAIN

# =========================================

def main():

    results = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "project": "DevSecOps CI/CD Evaluation"
        },

        "tools": {}
    }

    csv_rows = []

    for tool_name, config in TOOLS.items():

        parser = config["parser"]

        category = config["category"]

        expected = config.get("expected", GT_BY_CATEGORY.get(category, set()))

        detected = parser()

        metrics = calculate_metrics(detected, expected)

        results["tools"][tool_name] = {
            "category": category,
            "metrics": metrics
        }

        csv_rows.append([
            tool_name,
            category,
            metrics["TP"],
            metrics["FP"],
            metrics["FN"],
            metrics["precision"],
            metrics["recall"],
            metrics["f1_score"]
        ])

        print(f"✅ {tool_name}")
        print(metrics)

    # =====================================
    # SAVE JSON
    # =====================================

    with open("final_experiment_dataset.json", "w") as f:
        json.dump(results, f, indent=2)

    # =====================================
    # SAVE CSV
    # =====================================

    with open("results.csv", "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "Tool",
            "Category",
            "TP",
            "FP",
            "FN",
            "Precision",
            "Recall",
            "F1"
        ])

        writer.writerows(csv_rows)

    # =====================================
    # SAVE MARKDOWN
    # =====================================

    with open("results.md", "w") as f:

        f.write("# Security Tools Evaluation\n\n")

        f.write("| Tool | Category | TP | FP | FN | Precision | Recall | F1 |\n")
        f.write("|------|----------|----|----|----|-----------|--------|----|\n")

        for row in csv_rows:

            f.write(
                f"| {row[0]} | {row[1]} | {row[2]} | "
                f"{row[3]} | {row[4]} | {row[5]} | "
                f"{row[6]} | {row[7]} |\n"
            )

    print("\n✅ FINAL DATASET GENERATED")
    print("📁 final_experiment_dataset.json")
    print("📁 results.csv")
    print("📁 results.md")


if __name__ == "__main__":
    main()
