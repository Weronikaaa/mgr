import json
import os
import time
from datetime import datetime

def calculate_coverage(report_file, tool_name):
    """Oblicza coverage narzędzia (ile plików/linii kodu zostało przeanalizowanych)"""
    if tool_name == "bandit":
        with open(report_file) as f:
            data = json.load(f)
            return {
                'files_analyzed': len(data.get('metrics', {}).keys()),
                'lines_of_code': data.get('metrics', {}).get('_totals', {}).get('loc', 0),
                'tests_performed': len(data.get('results', []))
            }
    elif tool_name == "sonarqube":
        with open(report_file) as f:
            data = json.load(f)
            return {
                'files_analyzed': data.get('component', {}).get('measures', [{}])[0].get('value', 0),
                'lines_of_code': data.get('component', {}).get('measures', [{}])[1].get('value', 0),
                'coverage_percentage': data.get('component', {}).get('measures', [{}])[2].get('value', 0)
            }
    return {}

def calculate_severity_distribution(report_file, tool_type):
    """Oblicza dystrybucję severity dla podatności"""
    if tool_type == "bandit":
        with open(report_file) as f:
            data = json.load(f)
            results = data.get('results', [])
            return {
                'HIGH': sum(1 for r in results if r.get('issue_severity') == 'HIGH'),
                'MEDIUM': sum(1 for r in results if r.get('issue_severity') == 'MEDIUM'),
                'LOW': sum(1 for r in results if r.get('issue_severity') == 'LOW')
            }
    elif tool_type == "trivy":
        with open(report_file) as f:
            data = json.load(f)
            vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    severity = vuln.get('Severity', 'UNKNOWN')
                    if severity in vuln_counts:
                        vuln_counts[severity] += 1
            return vuln_counts
    return {}

def calculate_performance_metrics(start_time_ns, end_time_ns):
    """Oblicza metryki wydajnościowe"""
    duration_ns = end_time_ns - start_time_ns
    return {
        'duration_seconds': duration_ns / 1_000_000_000,
        'duration_milliseconds': duration_ns / 1_000_000,
        'start_time': datetime.fromtimestamp(start_time_ns / 1_000_000_000).isoformat(),
        'end_time': datetime.fromtimestamp(end_time_ns / 1_000_000_000).isoformat()
    }

def generate_comparison_table():
    """Generuje tabelę porównawczą dla dashboardu"""
    # Wczytaj metryki z wszystkich narzędzi
    tools_metrics = {}
    
    # Bandit
    if os.path.exists('bandit-report.json'):
        tools_metrics['Bandit'] = {
            'vulnerabilities': calculate_severity_distribution('bandit-report.json', 'bandit'),
            'coverage': calculate_coverage('bandit-report.json', 'bandit'),
            'type': 'SAST'
        }
    
    # SonarQube
    if os.path.exists('sonarqube-metrics.json'):
        tools_metrics['SonarQube'] = {
            'vulnerabilities': calculate_severity_distribution('sonarqube-metrics.json', 'sonarqube'),
            'coverage': calculate_coverage('sonarqube-metrics.json', 'sonarqube'),
            'type': 'SAST'
        }
    
    # Trivy
    if os.path.exists('trivy-report.json'):
        tools_metrics['Trivy'] = {
            'vulnerabilities': calculate_severity_distribution('trivy-report.json', 'trivy'),
            'type': 'SCA'
        }
    
    # OWASP
    if os.path.exists('owasp-report.json'):
        tools_metrics['OWASP Dependency Check'] = {
            'vulnerabilities': calculate_severity_distribution('owasp-report.json', 'owasp'),
            'type': 'SCA'
        }
    
    return tools_metrics

if __name__ == "__main__":
    comparison = generate_comparison_table()
    
    # Zapisz do pliku JSON dla dashboardu
    with open('metrics/comparison-metrics.json', 'w') as f:
        json.dump(comparison, f, indent=2)
    
    # Generuj raport tekstowy
    with open('metrics/comparison-report.md', 'w') as f:
        f.write("# Tool Comparison Report\n\n")
        f.write("| Tool | Type | Critical | High | Medium | Low | Coverage |\n")
        f.write("|------|------|----------|------|--------|-----|----------|\n")
        
        for tool, metrics in comparison.items():
            vulns = metrics.get('vulnerabilities', {})
            coverage = metrics.get('coverage', {}).get('coverage_percentage', 'N/A')
            f.write(f"| {tool} | {metrics.get('type', 'N/A')} | "
                   f"{vulns.get('CRITICAL', vulns.get('HIGH', 0))} | "
                   f"{vulns.get('HIGH', vulns.get('MEDIUM', 0))} | "
                   f"{vulns.get('MEDIUM', vulns.get('LOW', 0))} | "
                   f"{vulns.get('LOW', 0)} | {coverage}% |\n")
    
    print("✅ Comparison metrics generated!")
