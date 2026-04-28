#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import plotly.express as px
import pandas as pd
import numpy as np

def find_file(pattern):
    """Znajdź plik w dowolnym podkatalogu"""
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file == pattern or file.endswith(pattern):
                full_path = os.path.join(root, file)
                print(f"Found {pattern} at: {full_path}")
                return full_path
    print(f"Warning: {pattern} not found")
    return None

def load_bandit_metrics():
    """Load Bandit SAST results"""
    bandit_file = find_file('bandit-report.json')
    if not bandit_file:
        return {'vulnerabilities': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    with open(bandit_file, 'r') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    return {
        'vulnerabilities': len(results),
        'high': sum(1 for r in results if r.get('issue_severity') == 'HIGH'),
        'medium': sum(1 for r in results if r.get('issue_severity') == 'MEDIUM'),
        'low': sum(1 for r in results if r.get('issue_severity') == 'LOW')
    }

def load_semgrep_metrics():
    """Load Semgrep SAST results"""
    semgrep_file = find_file('semgrep-report.json')
    if not semgrep_file:
        return {'vulnerabilities': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    with open(semgrep_file, 'r') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    severity_map = {'ERROR': 'critical', 'WARNING': 'high', 'INFO': 'medium'}
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for r in results:
        sev = r.get('extra', {}).get('severity', 'INFO')
        mapped = severity_map.get(sev, 'medium')
        severity_counts[mapped] += 1
    
    return {
        'vulnerabilities': len(results),
        'critical': severity_counts['critical'],
        'high': severity_counts['high'],
        'medium': severity_counts['medium'],
        'low': severity_counts['low']
    }

def load_sonarqube_metrics():
    """Load SonarQube metrics"""
    sonar_file = find_file('sonarqube-metrics.json')
    if not sonar_file:
        return {'vulnerabilities': 0, 'bugs': 0, 'code_smells': 0, 'coverage': 0, 'security_hotspots': 0}
    
    with open(sonar_file, 'r') as f:
        data = json.load(f)
    
    measures = data.get('component', {}).get('measures', [])
    result = {'vulnerabilities': 0, 'bugs': 0, 'code_smells': 0, 'coverage': 0, 'security_hotspots': 0}
    
    for m in measures:
        metric = m.get('metric')
        value = m.get('value', '0')
        if metric == 'vulnerabilities':
            result['vulnerabilities'] = int(value)
        elif metric == 'bugs':
            result['bugs'] = int(value)
        elif metric == 'code_smells':
            result['code_smells'] = int(value)
        elif metric == 'coverage':
            try:
                result['coverage'] = float(value)
            except:
                result['coverage'] = 0
        elif metric == 'security_hotspots':
            result['security_hotspots'] = int(value)
    
    return result

def load_gitleaks_metrics():
    """Load Gitleaks secret scan results"""
    gitleaks_file = find_file('gitleaks-report.json')
    if not gitleaks_file:
        return {'total_leaks': 0, 'critical': 0, 'high': 0}
    
    with open(gitleaks_file, 'r') as f:
        data = json.load(f)
    
    # Format: lista bezpośrednia
    if isinstance(data, list):
        leaks = data
        return {
            'total_leaks': len(leaks),
            'secrets': [{'file': l.get('File', 'unknown'), 'line': l.get('StartLine', 0), 
                        'description': l.get('Description', l.get('description', 'Secret found'))} 
                       for l in leaks[:10]]
        }
    # Format: z polem 'leaks'
    elif 'leaks' in data:
        leaks = data.get('leaks', [])
        return {'total_leaks': len(leaks), 'secrets': []}
    else:
        return {'total_leaks': 0, 'secrets': []}

def load_trufflehog_metrics():
    """Load TruffleHog secret scan results"""
    trufflehog_file = find_file('trufflehog-report.json')
    if not trufflehog_file:
        return {'total_secrets': 0, 'detectors': []}
    
    with open(trufflehog_file, 'r') as f:
        lines = f.readlines()
    
    findings = []
    for line in lines:
        try:
            findings.append(json.loads(line))
        except:
            continue
    
    detectors = list(set(f.get('DetectorName', 'unknown') for f in findings))
    
    return {
        'total_secrets': len(findings),
        'detectors': detectors,
        'critical': sum(1 for f in findings if 'credential' in f.get('DetectorName', '').lower()),
        'high': sum(1 for f in findings if 'token' in f.get('DetectorName', '').lower()),
        'medium': len(findings) - sum(1 for f in findings if 'credential' in f.get('DetectorName', '').lower() or 'token' in f.get('DetectorName', '').lower())
    }

def load_trivy_fs_metrics():
    """Load Trivy filesystem scan results"""
    trivy_file = find_file('trivy-report.json')
    if not trivy_file:
        return {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0}
    
    with open(trivy_file, 'r') as f:
        data = json.load(f)
    
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', 'UNKNOWN')
            if severity in counts:
                counts[severity] += 1
    
    return {**counts, 'total': sum(counts.values())}

def load_trivy_container_metrics():
    """Load Trivy container scan results"""
    container_file = find_file('trivy-image.json')
    if not container_file:
        return {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0}
    
    with open(container_file, 'r') as f:
        data = json.load(f)
    
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', 'UNKNOWN')
            if severity in counts:
                counts[severity] += 1
    
    return {**counts, 'total': sum(counts.values())}

def load_grype_metrics():
    """Load Grype container scan results"""
    grype_file = find_file('grype-report.json')
    if not grype_file:
        return {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0}
    
    with open(grype_file, 'r') as f:
        data = json.load(f)
    
    matches = data.get('matches', [])
    severity_map = {'Critical': 'CRITICAL', 'High': 'HIGH', 'Medium': 'MEDIUM', 'Low': 'LOW', 'Negligible': 'LOW'}
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    for match in matches:
        sev = match.get('vulnerability', {}).get('severity', 'Low')
        mapped = severity_map.get(sev, 'LOW')
        counts[mapped] += 1
    
    return {**counts, 'total': len(matches)}

def load_tool_metrics():
    """Load metrics from all tools"""
    return {
        'bandit': load_bandit_metrics(),
        'semgrep': load_semgrep_metrics(),
        'sonarqube': load_sonarqube_metrics(),
        'gitleaks': load_gitleaks_metrics(),
        'trufflehog': load_trufflehog_metrics(),
        'trivy_fs': load_trivy_fs_metrics(),
        'trivy_container': load_trivy_container_metrics(),
        'grype': load_grype_metrics(),
        'timestamp': datetime.now().isoformat(),
        'run_id': os.getenv('GITHUB_RUN_ID', 'N/A'),
        'branch': os.getenv('GITHUB_REF_NAME', 'N/A')
    }

def create_comparison_charts(metrics):
    """Create comparison charts for SAST and SCA tools"""
    os.makedirs('dashboard', exist_ok=True)
    
    # SAST Tools Comparison
    sast_tools = ['Bandit', 'Semgrep', 'SonarQube']
    sast_counts = [
        metrics['bandit']['vulnerabilities'],
        metrics['semgrep']['vulnerabilities'],
        metrics['sonarqube']['vulnerabilities']
    ]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(sast_tools, sast_counts, color=['#667eea', '#48bb78', '#ed8936'])
    ax.set_title('SAST Tools Comparison: Total Vulnerabilities Detected')
    ax.set_ylabel('Number of Vulnerabilities')
    for bar, count in zip(bars, sast_counts):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                   str(count), ha='center', va='bottom')
    plt.tight_layout()
    plt.savefig('dashboard/sast_comparison.png')
    plt.close()
    
    # Secret Scanning Tools Comparison
    secret_tools = ['Gitleaks', 'TruffleHog']
    secret_counts = [
        metrics['gitleaks']['total_leaks'],
        metrics['trufflehog']['total_secrets']
    ]
    
    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.bar(secret_tools, secret_counts, color=['#9b59b6', '#e74c3c'])
    ax.set_title('Secret Scanning Tools Comparison')
    ax.set_ylabel('Number of Secrets Found')
    for bar, count in zip(bars, secret_counts):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                   str(count), ha='center', va='bottom')
    plt.tight_layout()
    plt.savefig('dashboard/secret_comparison.png')
    plt.close()
    
    # Container Scanning Tools Comparison
    container_tools = ['Trivy Container', 'Grype']
    container_critical = [
        metrics['trivy_container']['CRITICAL'],
        metrics['grype']['CRITICAL']
    ]
    container_high = [
        metrics['trivy_container']['HIGH'],
        metrics['grype']['HIGH']
    ]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(container_tools))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, container_critical, width, label='Critical', color='darkred')
    bars2 = ax.bar(x + width/2, container_high, width, label='High', color='orange')
    
    ax.set_xlabel('Tool')
    ax.set_ylabel('Count')
    ax.set_title('Container Scanning Tools: Critical & High Vulnerabilities')
    ax.set_xticks(x)
    ax.set_xticklabels(container_tools)
    ax.legend()
    
    plt.tight_layout()
    plt.savefig('dashboard/container_comparison.png')
    plt.close()

def create_severity_charts(metrics):
    """Create severity distribution charts for each tool"""
    os.makedirs('dashboard', exist_ok=True)
    
    # Bandit severity
    bandit_sev = [metrics['bandit']['high'], metrics['bandit']['medium'], metrics['bandit']['low']]
    if sum(bandit_sev) > 0:
        fig, ax = plt.subplots(figsize=(8, 6))
        bars = ax.bar(['High', 'Medium', 'Low'], bandit_sev, color=['darkred', 'orange', 'gold'])
        ax.set_title('Bandit: Vulnerabilities by Severity')
        ax.set_ylabel('Count')
        plt.tight_layout()
        plt.savefig('dashboard/bandit_severity.png')
        plt.close()
    
    # Semgrep severity
    semgrep_sev = [metrics['semgrep']['critical'], metrics['semgrep']['high'], 
                   metrics['semgrep']['medium'], metrics['semgrep']['low']]
    if sum(semgrep_sev) > 0:
        fig, ax = plt.subplots(figsize=(8, 6))
        bars = ax.bar(['Critical', 'High', 'Medium', 'Low'], semgrep_sev, 
                      color=['darkred', 'red', 'orange', 'gold'])
        ax.set_title('Semgrep: Vulnerabilities by Severity')
        ax.set_ylabel('Count')
        plt.tight_layout()
        plt.savefig('dashboard/semgrep_severity.png')
        plt.close()
    
    # Trivy FS severity
    trivy_sev = [metrics['trivy_fs']['CRITICAL'], metrics['trivy_fs']['HIGH'], 
                 metrics['trivy_fs']['MEDIUM'], metrics['trivy_fs']['LOW']]
    if sum(trivy_sev) > 0:
        fig, ax = plt.subplots(figsize=(8, 6))
        bars = ax.bar(['Critical', 'High', 'Medium', 'Low'], trivy_sev,
                      color=['darkred', 'red', 'orange', 'gold'])
        ax.set_title('Trivy Filesystem: Vulnerabilities by Severity')
        ax.set_ylabel('Count')
        plt.tight_layout()
        plt.savefig('dashboard/trivy_fs_severity.png')
        plt.close()

def create_summary_table(metrics):
    """Create summary table of all findings"""
    os.makedirs('dashboard', exist_ok=True)
    
    data = []
    
    # SAST Tools
    data.append(['Bandit (SAST)', metrics['bandit']['vulnerabilities'], 
                 metrics['bandit']['high'], metrics['bandit']['medium'], metrics['bandit']['low']])
    data.append(['Semgrep (SAST)', metrics['semgrep']['vulnerabilities'],
                 metrics['semgrep']['high'], metrics['semgrep']['medium'], metrics['semgrep']['low']])
    data.append(['SonarQube (SAST)', metrics['sonarqube']['vulnerabilities'],
                 'N/A', 'N/A', 'N/A'])
    
    # Secret Scanning
    data.append(['Gitleaks (Secrets)', metrics['gitleaks']['total_leaks'], 'N/A', 'N/A', 'N/A'])
    data.append(['TruffleHog (Secrets)', metrics['trufflehog']['total_secrets'], 'N/A', 'N/A', 'N/A'])
    
    # SCA/Container
    data.append(['Trivy FS (SCA)', metrics['trivy_fs']['total'],
                 metrics['trivy_fs']['CRITICAL'], metrics['trivy_fs']['HIGH'], 
                 metrics['trivy_fs']['MEDIUM']])
    data.append(['Trivy Container', metrics['trivy_container']['total'],
                 metrics['trivy_container']['CRITICAL'], metrics['trivy_container']['HIGH'],
                 metrics['trivy_container']['MEDIUM']])
    data.append(['Grype (Container)', metrics['grype']['total'],
                 metrics['grype']['CRITICAL'], metrics['grype']['HIGH'],
                 metrics['grype']['MEDIUM']])
    
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.axis('tight')
    ax.axis('off')
    
    columns = ['Tool', 'Total', 'Critical', 'High', 'Medium']
    table = ax.table(cellText=data, colLabels=columns, cellLoc='center', loc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.5, 1.8)
    
    # Color coding for critical and high
    for i, row in enumerate(data):
        for j, val in enumerate(row):
            if j == 2 and str(val) not in ['N/A', '0'] and int(val) if str(val).isdigit() else 0 > 0:
                table[(i+1, j)].set_facecolor('#ffcccc')
            elif j == 3 and str(val) not in ['N/A', '0'] and int(val) if str(val).isdigit() else 0 > 0:
                table[(i+1, j)].set_facecolor('#ffe6cc')
    
    plt.title('Complete Security Findings Summary', pad=20, fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig('dashboard/summary_table.png', bbox_inches='tight')
    plt.close()

def generate_html_dashboard(metrics):
    """Generate main HTML dashboard"""
    
    total_vulns = (metrics['bandit']['vulnerabilities'] + 
                   metrics['semgrep']['vulnerabilities'] +
                   metrics['trivy_fs']['total'] + 
                   metrics['trivy_container']['total'] +
                   metrics['grype']['total'])
    
    total_critical = (metrics['trivy_fs']['CRITICAL'] + 
                      metrics['trivy_container']['CRITICAL'] +
                      metrics['grype']['CRITICAL'])
    
    total_secrets = metrics['gitleaks']['total_leaks'] + metrics['trufflehog']['total_secrets']
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DevSecOps Security Dashboard</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{ max-width: 1400px; margin: 0 auto; }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border-radius: 15px;
                padding: 30px;
                margin-bottom: 30px;
                text-align: center;
                color: white;
            }}
            .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
            .timestamp {{ opacity: 0.9; font-size: 0.9em; }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: white;
                border-radius: 15px;
                padding: 20px;
                text-align: center;
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                transition: transform 0.3s;
            }}
            .stat-card:hover {{ transform: translateY(-5px); }}
            .stat-number {{ font-size: 2.5em; font-weight: bold; margin: 10px 0; }}
            .stat-number.critical {{ color: #dc3545; }}
            .stat-number.secrets {{ color: #fd7e14; }}
            .stat-number.total {{ color: #667eea; }}
            .stat-label {{ color: #666; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
            .card {{
                background: white;
                border-radius: 15px;
                padding: 25px;
                margin-bottom: 30px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }}
            .card h2 {{
                color: #333;
                margin-bottom: 20px;
                padding-bottom: 10px;
                border-bottom: 3px solid #667eea;
                display: inline-block;
            }}
            .grid-2 {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
                gap: 30px;
                margin-bottom: 30px;
            }}
            img {{ width: 100%; height: auto; border-radius: 10px; }}
            .badge {{
                display: inline-block;
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 0.75em;
                font-weight: bold;
            }}
            .badge.critical {{ background: #dc3545; color: white; }}
            .badge.high {{ background: #fd7e14; color: white; }}
            .badge.medium {{ background: #ffc107; color: #333; }}
            .footer {{
                text-align: center;
                padding: 20px;
                color: #888;
                font-size: 0.8em;
            }}
            @media (max-width: 768px) {{
                .grid-2 {{ grid-template-columns: 1fr; }}
                .header h1 {{ font-size: 1.5em; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ DevSecOps Security Dashboard</h1>
                <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                <div class="timestamp">Run ID: {metrics['run_id']} | Branch: {metrics['branch']}</div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Total Vulnerabilities</div>
                    <div class="stat-number total">{total_vulns}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Critical Issues</div>
                    <div class="stat-number critical">{total_critical}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Secrets Found</div>
                    <div class="stat-number secrets">{total_secrets}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">SAST Tools</div>
                    <div class="stat-number total">3</div>
                </div>
            </div>
            
            <div class="grid-2">
                <div class="card">
                    <h2>🐍 SAST Tools Comparison</h2>
                    <img src="sast_comparison.png" alt="SAST Comparison">
                    <p style="margin-top: 15px;">
                        <strong>Bandit:</strong> {metrics['bandit']['vulnerabilities']} vulns<br>
                        <strong>Semgrep:</strong> {metrics['semgrep']['vulnerabilities']} vulns<br>
                        <strong>SonarQube:</strong> {metrics['sonarqube']['vulnerabilities']} vulns
                    </p>
                </div>
                
                <div class="card">
                    <h2>🔑 Secret Scanning Comparison</h2>
                    <img src="secret_comparison.png" alt="Secret Scanning Comparison">
                    <p style="margin-top: 15px;">
                        <strong>Gitleaks:</strong> {metrics['gitleaks']['total_leaks']} secrets<br>
                        <strong>TruffleHog:</strong> {metrics['trufflehog']['total_secrets']} secrets
                    </p>
                </div>
            </div>
            
            <div class="grid-2">
                <div class="card">
                    <h2>🐳 Container Scanning Comparison</h2>
                    <img src="container_comparison.png" alt="Container Comparison">
                    <p style="margin-top: 15px;">
                        <strong>Trivy Container:</strong> {metrics['trivy_container']['total']} total 
                        (Critical: {metrics['trivy_container']['CRITICAL']})<br>
                        <strong>Grype:</strong> {metrics['grype']['total']} total 
                        (Critical: {metrics['grype']['CRITICAL']})
                    </p>
                </div>
                
                <div class="card">
                    <h2>📊 Severity Distribution</h2>
                    <img src="bandit_severity.png" alt="Bandit Severity">
                    <p style="margin-top: 15px;">
                        <strong>Bandit High:</strong> {metrics['bandit']['high']} | 
                        <strong>Semgrep Critical:</strong> {metrics['semgrep']['critical']}
                    </p>
                </div>
            </div>
            
            <div class="card">
                <h2>📋 Complete Summary - All Tools</h2>
                <img src="summary_table.png" alt="Summary Table">
            </div>
            
            <div class="card">
                <h2>🔐 Detailed Secrets Found</h2>
                <ul style="margin-top: 15px;">
                    {' '.join([f'<li><strong>{s.get("description", "Secret")}</strong> - File: {s.get("file", "unknown")}:{s.get("line", "?")}</li>' for s in metrics['gitleaks'].get('secrets', [])[:5]])}
                    {f'<li>... and {metrics["trufflehog"]["total_secrets"]} more from TruffleHog</li>' if metrics['trufflehog']['total_secrets'] > 0 else ''}
                </ul>
            </div>
            
            <div class="footer">
                Generated by DevSecOps Pipeline | Tools: Bandit, Semgrep, SonarQube, Gitleaks, TruffleHog, Trivy, Grype
            </div>
        </div>
    </body>
    </html>
    """
    
    with open('dashboard/index.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("✅ Dashboard generated successfully!")
    print(f"📁 Dashboard location: dashboard/index.html")

def save_metrics_json(metrics):
    """Save all metrics to JSON file for reference"""
    with open('dashboard/metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    print("✅ Metrics saved to dashboard/metrics.json")

def main():
    """Main function"""
    print("=" * 50)
    print("🚀 Generating Security Metrics Dashboard")
    print("=" * 50)
    
    try:
        # Load all metrics
        metrics = load_tool_metrics()
        
        # Create dashboard directory
        os.makedirs('dashboard', exist_ok=True)
        
        # Create all charts
        create_comparison_charts(metrics)
        create_severity_charts(metrics)
        create_summary_table(metrics)
        
        # Generate HTML dashboard
        generate_html_dashboard(metrics)
        
        # Save metrics JSON
        save_metrics_json(metrics)
        
        print("\n" + "=" * 50)
        print("✅ Dashboard generation completed successfully!")
        print("📊 Check the 'dashboard' directory for output files")
        print("=" * 50)
        
    except Exception as e:
        print(f"❌ Error generating dashboard: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
