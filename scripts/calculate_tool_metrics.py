#!/usr/bin/env python3
import json
import os
import sys
import argparse
from datetime import datetime

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tool', type=str, required=True, help='Tool name (bandit, trivy, etc.)')
    parser.add_argument('--start', type=str, help='Start time in nanoseconds')
    parser.add_argument('--end', type=str, help='End time in nanoseconds')
    return parser.parse_args()
    
def calculate_duration(start_ns, end_ns):
    """Calculate duration in seconds and milliseconds"""
    if not start_ns or not end_ns:
        return {'duration_seconds': 'N/A', 'duration_ms': 'N/A'}
    
    duration_ns = int(end_ns) - int(start_ns)
    return {
        'duration_seconds': round(duration_ns / 1_000_000_000, 2),
        'duration_ms': round(duration_ns / 1_000_000, 2)
    }

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
def get_bandit_metrics():
    """Extract Bandit metrics from report"""
    if not os.path.exists('bandit-report.json'):
        return None
    
    with open('bandit-report.json') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    metrics = data.get('metrics', {}).get('_totals', {})
    
    return {
        'total_vulnerabilities': len(results),
        'severity': {
            'HIGH': sum(1 for r in results if r.get('issue_severity') == 'HIGH'),
            'MEDIUM': sum(1 for r in results if r.get('issue_severity') == 'MEDIUM'),
            'LOW': sum(1 for r in results if r.get('issue_severity') == 'LOW')
        },
        'confidence': {
            'HIGH': metrics.get('CONFIDENCE.HIGH', 0),
            'MEDIUM': metrics.get('CONFIDENCE.MEDIUM', 0),
            'LOW': metrics.get('CONFIDENCE.LOW', 0)
        },
        'lines_of_code': metrics.get('loc', 0),
        'nosec_count': metrics.get('nosec', 0)
    }

def save_metrics(tool_name, metrics, duration):
    """Save metrics to JSON file"""
    os.makedirs('metrics', exist_ok=True)
    
    # Load existing metrics if any
    output_file = 'metrics/tool-metrics.json'
    all_metrics = {}
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            all_metrics = json.load(f)
    
    # Add new metrics
    all_metrics[tool_name] = {
        'timestamp': datetime.now().isoformat(),
        'duration': duration,
        'metrics': metrics
    }
    
    # Save to file
    with open(output_file, 'w') as f:
        json.dump(all_metrics, f, indent=2)
    
    print(f"✅ Saved metrics for {tool_name}")
    print(f"   Duration: {duration.get('duration_seconds', 'N/A')} seconds")
    
    if metrics:
        if 'total_vulnerabilities' in metrics:
            print(f"   Vulnerabilities: {metrics['total_vulnerabilities']}")
        elif 'CRITICAL' in metrics:
            total = sum(metrics.values())
            print(f"   Vulnerabilities: {total}")

def main():
    args = parse_arguments()
    
    # Calculate duration
    duration = calculate_duration(args.start, args.end)
    
    # Get tool-specific metrics
    metrics = None
    if args.tool == 'bandit':
        metrics = get_bandit_metrics()
    # Add more tools here (trivy, etc.)
    
    # Save metrics
    save_metrics(args.tool, metrics, duration)

if __name__ == "__main__":
    # Utwórz katalog metrics jeśli nie istnieje
    os.makedirs('metrics', exist_ok=True)
    
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
    
    print("✅ Comparison metrics generated successfully in metrics/ directory!")
