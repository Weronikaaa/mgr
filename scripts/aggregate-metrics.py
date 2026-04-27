import json
import os

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None

metrics = {}

# -------- Bandit --------
bandit = load_json("bandit-report/bandit-report.json")
metrics["bandit_issues"] = len(bandit.get("results", [])) if bandit else 0

# -------- Gitleaks --------
gitleaks = load_json("gitleaks-report/gitleaks-report.json")
metrics["secrets"] = len(gitleaks) if gitleaks else 0

# -------- Trivy FS --------
def count_trivy(data):
    if not data:
        return 0
    total = 0
    for r in data.get("Results", []):
        total += len(r.get("Vulnerabilities", []))
    return total

metrics["sca_vulns"] = count_trivy(load_json("trivy-report/trivy-report.json"))
metrics["container_vulns"] = count_trivy(load_json("trivy-image/trivy-image.json"))

# -------- zapis --------
os.makedirs("metrics", exist_ok=True)

with open("metrics/summary.json", "w") as f:
    json.dump(metrics, f, indent=2)

print("FINAL METRICS:", metrics)
