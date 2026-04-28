#!/usr/bin/env python3
import json
import os
import sys
import argparse
from datetime import datetime

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tool', type=str, required=True, help='Tool name (bandit, sonarqube, semgrep, gitleaks, trufflehog, trivy, grype)')
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

def get_bandit_metrics():
    """Extract Bandit metrics from report"""
    if not os.path.exists('bandit-report.json'):
        return None
    
    with open('bandit-report.json') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    metrics = data.get('metrics', {}).get('_totals', {})
    
    return {
        'tool_type': 'SAST',
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
        'nosec_count': metrics.get('nosec', 0),
        'files_analyzed': len(data.get('metrics', {}).keys())
    }

def get_sonarqube_metrics():
    """Extract SonarQube metrics from report"""
    if not os.path.exists('sonarqube-metrics.json'):
        return None
    
    with open('sonarqube-metrics.json') as f:
        data = json.load(f)
    
    measures = data.get('component', {}).get('measures', [])
    metrics_dict = {m.get('metric'): m.get('value') for m in measures}
    
    return {
        'tool_type': 'SAST',
        'bugs': int(metrics_dict.get('bugs', 0)),
        'vulnerabilities': int(metrics_dict.get('vulnerabilities', 0)),
        'security_hotspots': int(metrics_dict.get('security_hotspots', 0)),
        'code_smells': int(metrics_dict.get('code_smells', 0)),
        'coverage': float(metrics_dict.get('coverage', 0)),
        'duplicated_lines_density': float(metrics_dict.get('duplicated_lines_density', 0)),
        'severity': {
            'CRITICAL': int(metrics_dict.get('vulnerabilities', 0)),
            'HIGH': int(metrics_dict.get('bugs', 0)),
            'MEDIUM': int(metrics_dict.get('code_smells', 0)),
            'LOW': int(metrics_dict.get('security_hotspots', 0))
        }
    }

def get_semgrep_metrics():
    """Extract Semgrep metrics from report"""
    if not os.path.exists('semgrep-report.json'):
        return None
    
    with open('semgrep-report.json') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    
    severity_map = {
        'ERROR': 'CRITICAL',
        'WARNING': 'HIGH',
        'INFO': 'MEDIUM'
    }
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for r in results:
        level = r.get('extra', {}).get('severity', 'INFO')
        mapped = severity_map.get(level, 'LOW')
        severity_counts[mapped] += 1
    
    return {
        'tool_type': 'SAST',
        'total_vulnerabilities': len(results),
        'severity': severity_counts,
        'files_analyzed': len(set(r.get('path', '') for r in results))
    }

def get_gitleaks_metrics():
    """Extract Gitleaks metrics from report"""
    if not os.path.exists('gitleaks-report.json'):
        return None
    
    with open('gitleaks-report.json') as f:
        data = json.load(f)
    
    findings = data if isinstance(data, list) else data.get('findings', [])
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for finding in findings:
        # Gitleaks nie ma severity, więc mapujemy po description
        desc = finding.get('description', '').lower()
        if 'password' in desc or 'api key' in desc or 'token' in desc:
            severity_counts['CRITICAL'] += 1
        elif 'secret' in desc or 'key' in desc:
            severity_counts['HIGH'] += 1
        else:
            severity_counts['MEDIUM'] += 1
    
    return {
        'tool_type': 'SECRET_SCAN',
        'total_secrets': len(findings),
        'severity': severity_counts,
        'leaks': [{'file': f.get('file', ''), 'line': f.get('startLine', 0), 
                   'secret': f.get('description', '')[:50]} for f in findings[:10]]
    }

def get_trufflehog_metrics():
    """Extract TruffleHog metrics from report"""
    if not os.path.exists('trufflehog-report.json'):
        return None
    
    with open('trufflehog-report.json') as f:
        lines = f.readlines()
    
    findings = []
    for line in lines:
        try:
            findings.append(json.loads(line))
        except:
            continue
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for finding in findings:
        detector = finding.get('DetectorName', '').lower()
        if 'credential' in detector or 'password' in detector or 'key' in detector:
            severity_counts['CRITICAL'] += 1
        elif 'token' in detector or 'secret' in detector:
            severity_counts['HIGH'] += 1
        else:
            severity_counts['MEDIUM'] += 1
    
    return {
        'tool_type': 'SECRET_SCAN',
        'total_secrets': len(findings),
        'severity': severity_counts,
        'detectors': list(set(f.get('DetectorName', 'unknown') for f in findings))
    }

def get_trivy_metrics(report_type='fs'):
    """Extract Trivy metrics from report (fs or image)"""
    filename = 'trivy-report.json' if report_type == 'fs' else 'trivy-image.json'
    if not os.path.exists(filename):
        return None
    
    with open(filename) as f:
        data = json.load(f)
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', 'UNKNOWN')
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    total = sum([v for k, v in severity_counts.items() if k != 'UNKNOWN'])
    
    return {
        'tool_type': 'SCA' if report_type == 'fs' else 'CONTAINER',
        'total_vulnerabilities': total,
        'severity': severity_counts,
        'targets': [r.get('Target', '') for r in data.get('Results', [])]
    }

def get_grype_metrics():
    """Extract Grype metrics from report"""
    if not os.path.exists('grype-report.json'):
        return None
    
    with open('grype-report.json') as f:
        data = json.load(f)
    
    matches = data.get('matches', [])
    
    severity_map = {
        'Critical': 'CRITICAL',
        'High': 'HIGH',
        'Medium': 'MEDIUM',
        'Low': 'LOW',
        'Negligible': 'LOW'
    }
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for match in matches:
        vuln = match.get('vulnerability', {})
        severity = vuln.get('severity', 'Low')
        mapped = severity_map.get(severity, 'LOW')
        severity_counts[mapped] += 1
    
    return {
        'tool_type': 'SCA_CONTAINER',
        'total_vulnerabilities': len(matches),
        'severity': severity_counts,
        'source': data.get('source', {}).get('target', {})
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
        elif 'total_secrets' in metrics:
            print(f"   Secrets found: {metrics['total_secrets']}")
        elif 'vulnerabilities' in metrics:
            print(f"   Vulnerabilities: {metrics.get('vulnerabilities', 0)}")

def generate_comparison_table():
    """Generates comparison table for all tools"""
    results = {}
    
    # SAST Tools
    if os.path.exists('bandit-report.json'):
        results['Bandit'] = get_bandit_metrics()
    
    if os.path.exists('sonarqube-metrics.json'):
        results['SonarQube'] = get_sonarqube_metrics()
    
    if os.path.exists('semgrep-report.json'):
        results['Semgrep'] = get_semgrep_metrics()
    
    # Secret Scanning Tools
    if os.path.exists('gitleaks-report.json'):
        results['Gitleaks'] = get_gitleaks_metrics()
    
    if os.path.exists('trufflehog-report.json'):
        results['TruffleHog'] = get_trufflehog_metrics()
    
    # SCA Tools
    if os.path.exists('trivy-report.json'):
        results['Trivy (SCA)'] = get_trivy_metrics('fs')
    
    # Container Scanning Tools
    if os.path.exists('trivy-image.json'):
        results['Trivy (Container)'] = get_trivy_metrics('image')
    
    if os.path.exists('grype-report.json'):
        results['Grype'] = get_grype_metrics()
    
    return results

def main():
    args = parse_arguments()
    
    # Calculate duration
    duration = calculate_duration(args.start, args.end)
    
    # Get tool-specific metrics
    metrics = None
    if args.tool == 'bandit':
        metrics = get_bandit_metrics()
    elif args.tool == 'sonarqube':
        metrics = get_sonarqube_metrics()
    elif args.tool == 'semgrep':
        metrics = get_semgrep_metrics()
    elif args.tool == 'gitleaks':
        metrics = get_gitleaks_metrics()
    elif args.tool == 'trufflehog':
        metrics = get_trufflehog_metrics()
    elif args.tool == 'trivy':
        # Sprawdź który raport istnieje
        if os.path.exists('trivy-image.json'):
            metrics = get_trivy_metrics('image')
        else:
            metrics = get_trivy_metrics('fs')
    elif args.tool == 'grype':
        metrics = get_grype_metrics()
    
    # Save metrics
    save_metrics(args.tool, metrics, duration)

if __name__ == "__main__":
    # Utwórz katalog metrics jeśli nie istnieje
    os.makedirs('metrics', exist_ok=True)
    
    # Jeśli uruchomiono bez argumentów, generuj porównanie
    if len(sys.argv) == 1:
        comparison = generate_comparison_table()
        
        # Zapisz do pliku JSON dla dashboardu
        with open('metrics/comparison-metrics.json', 'w') as f:
            json.dump(comparison, f, indent=2, default=str)
        
        # Generuj raport tekstowy
        with open('metrics/comparison-report.md', 'w') as f:
            f.write("# Tool Comparison Report\n\n")
            f.write("## SAST Tools\n\n")
            f.write("| Tool | Total | Critical | High | Medium | Low |\n")
            f.write("|------|-------|----------|------|--------|-----|\n")
            
            for tool, metrics in comparison.items():
                if not metrics:
                    continue
                if metrics.get('tool_type') == 'SAST':
                    severity = metrics.get('severity', {})
                    total = metrics.get('total_vulnerabilities', metrics.get('vulnerabilities', 
                           metrics.get('bugs', 0) + metrics.get('vulnerabilities', 0)))
                    f.write(f"| {tool} | {total} | {severity.get('CRITICAL', 0)} | "
                           f"{severity.get('HIGH', 0)} | {severity.get('MEDIUM', 0)} | "
                           f"{severity.get('LOW', 0)} |\n")
            
            f.write("\n## Secret Scanning Tools\n\n")
            f.write("| Tool | Total Secrets Found |\n")
            f.write("|------|---------------------|\n")
            
            for tool, metrics in comparison.items():
                if metrics and metrics.get('tool_type') == 'SECRET_SCAN':
                    f.write(f"| {tool} | {metrics.get('total_secrets', 0)} |\n")
            
            f.write("\n## SCA & Container Scanning Tools\n\n")
            f.write("| Tool | Total Vulnerabilities | Critical | High | Medium | Low |\n")
            f.write("|------|----------------------|----------|------|--------|-----|\n")
            
            for tool, metrics in comparison.items():
                if metrics and metrics.get('tool_type') in ['SCA', 'CONTAINER', 'SCA_CONTAINER']:
                    severity = metrics.get('severity', {})
                    f.write(f"| {tool} | {metrics.get('total_vulnerabilities', 0)} | "
                           f"{severity.get('CRITICAL', 0)} | {severity.get('HIGH', 0)} | "
                           f"{severity.get('MEDIUM', 0)} | {severity.get('LOW', 0)} |\n")
        
        print("✅ Comparison metrics generated successfully in metrics/ directory!")
    else:
        main()
