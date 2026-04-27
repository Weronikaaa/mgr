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
    # Szukaj w bieżącym katalogu i podkatalogach
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file == pattern or file.endswith(pattern):
                full_path = os.path.join(root, file)
                print(f"Found {pattern} at: {full_path}")
                return full_path
    print(f"Warning: {pattern} not found")
    return None
    
def load_bandit_metrics():
    """Load Bandit SAST results correctly"""
    bandit_file = find_file('bandit-report.json')
    if not bandit_file:
        print("Bandit report not found")
        return {'vulnerabilities': 0, 'high_severity': 0, 'medium_severity': 0, 'low_severity': 0}
    
    with open(bandit_file, 'r') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    
    print(f"Bandit: Found {len(results)} issues")
    
    high = sum(1 for r in results if r.get('issue_severity') == 'HIGH')
    medium = sum(1 for r in results if r.get('issue_severity') == 'MEDIUM')
    low = sum(1 for r in results if r.get('issue_severity') == 'LOW')
    
    for r in results:
        print(f"  - {r.get('issue_severity')}: {r.get('test_name', 'unknown')}")
    
    return {
        'vulnerabilities': len(results),
        'high_severity': high,
        'medium_severity': medium,
        'low_severity': low,
    }
    
def load_trivy_metrics():
    """Load Trivy filesystem scan results"""
    trivy_file = find_file('trivy-report.json')
    if not trivy_file:
        print("Trivy report not found")
        return {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    with open(trivy_file, 'r') as f:
        data = json.load(f)
    
    vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    if 'Results' in data:
        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                severity = vuln.get('Severity', 'UNKNOWN')
                if severity in vuln_counts:
                    vuln_counts[severity] += 1
    
    print(f"Trivy FS: {sum(vuln_counts.values())} total vulnerabilities")
    return vuln_counts

def load_container_metrics():
    """Load Trivy container scan results"""
    container_file = find_file('trivy-image.json')
    if not container_file:
        print("Container report not found")
        return {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    with open(container_file, 'r') as f:
        data = json.load(f)
    
    vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    if 'Results' in data:
        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                severity = vuln.get('Severity', 'UNKNOWN')
                if severity in vuln_counts:
                    vuln_counts[severity] += 1
    
    print(f"Container: {sum(vuln_counts.values())} total vulnerabilities")
    return vuln_counts

def load_gitleaks_metrics():
    """Load Gitleaks secret scan results"""
    gitleaks_file = find_file('gitleaks-report.json')
    if not gitleaks_file:
        print("Gitleaks report not found")
        return {'total_leaks': 0, 'high_entropy': 0}
    
    with open(gitleaks_file, 'r') as f:
        data = json.load(f)
        leaks = data.get('leaks', [])
        
    print(f"Gitleaks: Found {len(leaks)} secrets")
    return {
        'total_leaks': len(leaks),
        'high_entropy': sum(1 for l in leaks if l.get('Entropy', 0) > 6.0)
    }

def create_visualizations():
    """Create all visualizations for the dashboard"""
    
    # Stwórz katalog dashboard jeśli nie istnieje
    os.makedirs('dashboard', exist_ok=True)
    
    # Wczytaj wszystkie metryki
    bandit_data = load_bandit_metrics()
    trivy_data = load_trivy_metrics()
    container_data = load_container_metrics()
    gitleaks_data = load_gitleaks_metrics()
    
    # 1. Wykres dla Bandit
    fig, ax = plt.subplots(figsize=(10, 6))
    severities = ['High', 'Medium', 'Low']
    counts = [bandit_data['high_severity'], bandit_data['medium_severity'], bandit_data['low_severity']]
    colors = ['darkred', 'orange', 'yellow']
    
    bars = ax.bar(severities, counts, color=colors)
    ax.set_title('Bandit SAST Vulnerabilities by Severity')
    ax.set_ylabel('Count')
    ax.set_xlabel('Severity Level')
    
    for bar, count in zip(bars, counts):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                   str(count), ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig('dashboard/bandit_vulns.png')
    plt.close()
    
    # 2. Wykres dla Trivy FS
    fig, ax = plt.subplots(figsize=(10, 6))
    severities = list(trivy_data.keys())
    counts = list(trivy_data.values())
    colors = {'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow', 'UNKNOWN': 'gray'}
    bar_colors = [colors.get(s, 'blue') for s in severities]
    
    bars = ax.bar(severities, counts, color=bar_colors)
    ax.set_title('Trivy Filesystem Scan Vulnerabilities')
    ax.set_ylabel('Count')
    ax.set_xlabel('Severity Level')
    
    for bar, count in zip(bars, counts):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                   str(count), ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig('dashboard/trivy_fs_vulns.png')
    plt.close()
    
    # 3. Wykres dla Container scan
    fig, ax = plt.subplots(figsize=(10, 6))
    severities = list(container_data.keys())
    counts = list(container_data.values())
    bar_colors = [colors.get(s, 'blue') for s in severities]
    
    bars = ax.bar(severities, counts, color=bar_colors)
    ax.set_title('Container Image Vulnerabilities')
    ax.set_ylabel('Count')
    ax.set_xlabel('Severity Level')
    
    for bar, count in zip(bars, counts):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                   str(count), ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig('dashboard/container_vulns.png')
    plt.close()
    
    # 4. Podsumowanie w formie tabeli
    summary_data = {
        'Tool': ['Bandit SAST', 'Trivy FS', 'Trivy Container', 'Gitleaks'],
        'Critical': [0, trivy_data['CRITICAL'], container_data['CRITICAL'], 0],
        'High': [bandit_data['high_severity'], trivy_data['HIGH'], container_data['HIGH'], 0],
        'Medium': [bandit_data['medium_severity'], trivy_data['MEDIUM'], container_data['MEDIUM'], 0],
        'Low': [bandit_data['low_severity'], trivy_data['LOW'], container_data['LOW'], gitleaks_data['total_leaks']]
    }
    
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.axis('tight')
    ax.axis('off')
    
    table = ax.table(cellText=[[
        summary_data['Tool'][i],
        summary_data['Critical'][i],
        summary_data['High'][i],
        summary_data['Medium'][i],
        summary_data['Low'][i]
    ] for i in range(4)],
    colLabels=['Tool', 'Critical', 'High', 'Medium', 'Low'],
    cellLoc='center',
    loc='center')
    
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.5)
    
    # Color coding
    for i in range(4):
        for j in range(5):
            if j > 0:  # Skip tool name column
                value = int(table[(i+1, j)].get_text().get_text())
                if value > 0:
                    if j == 1:  # Critical
                        table[(i+1, j)].set_facecolor('#ffcccc')
                    elif j == 2:  # High
                        table[(i+1, j)].set_facecolor('#ffe6cc')
    
    plt.title('Security Findings Summary', pad=20, fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig('dashboard/summary_table.png', bbox_inches='tight')
    plt.close()
    
    # 5. Generuj główny dashboard HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Metrics Dashboard</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{ 
                max-width: 1400px; 
                margin: 0 auto;
            }}
            .header {{
                background: white;
                border-radius: 15px;
                padding: 30px;
                margin-bottom: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                text-align: center;
            }}
            .header h1 {{
                color: #333;
                font-size: 2.5em;
                margin-bottom: 10px;
            }}
            .timestamp {{
                color: #666;
                font-size: 0.9em;
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: white;
                border-radius: 15px;
                padding: 25px;
                text-align: center;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                transition: transform 0.3s;
            }}
            .stat-card:hover {{
                transform: translateY(-5px);
            }}
            .stat-number {{
                font-size: 2.5em;
                font-weight: bold;
                color: #667eea;
                margin: 10px 0;
            }}
            .stat-label {{
                color: #666;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
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
                grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
                gap: 30px;
                margin-bottom: 30px;
            }}
            img {{
                width: 100%;
                height: auto;
                border-radius: 10px;
            }}
            .severity-badge {{
                display: inline-block;
                padding: 3px 8px;
                border-radius: 5px;
                font-size: 0.8em;
                font-weight: bold;
            }}
            .critical {{ background: #dc3545; color: white; }}
            .high {{ background: #fd7e14; color: white; }}
            .medium {{ background: #ffc107; color: #333; }}
            .low {{ background: #28a745; color: white; }}
            @media (max-width: 768px) {{
                .grid-2 {{ grid-template-columns: 1fr; }}
                .header h1 {{ font-size: 1.5em; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Security Metrics Dashboard</h1>
                <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                <div class="timestamp">Pipeline Run: {os.getenv('GITHUB_RUN_ID', 'N/A')}</div>
                <div class="timestamp">Branch: {os.getenv('GITHUB_REF_NAME', 'N/A')}</div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Total Vulnerabilities</div>
                    <div class="stat-number">{sum(trivy_data.values()) + sum(container_data.values()) + bandit_data['vulnerabilities']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Critical Issues</div>
                    <div class="stat-number" style="color: #dc3545;">{trivy_data['CRITICAL'] + container_data['CRITICAL']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Secrets Found</div>
                    <div class="stat-number" style="color: #fd7e14;">{gitleaks_data['total_leaks']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Tools Used</div>
                    <div class="stat-number">4</div>
                </div>
            </div>
            
            <div class="grid-2">
                <div class="card">
                    <h2>🐍 Bandit SAST Results</h2>
                    <img src="bandit_vulns.png" alt="Bandit Vulnerabilities">
                    <p style="margin-top: 15px;">
                        <strong>Summary:</strong> Found {bandit_data['vulnerabilities']} vulnerabilities
                        ({bandit_data['high_severity']} high, {bandit_data['medium_severity']} medium, {bandit_data['low_severity']} low)
                    </p>
                </div>
                
                <div class="card">
                    <h2>🔍 Gitleaks Secrets Scan</h2>
                    <img src="summary_table.png" alt="Summary Table">
                    <p style="margin-top: 15px;">
                        <strong>Secrets found:</strong> {gitleaks_data['total_leaks']} potential secrets
                        ({gitleaks_data['high_entropy']} with high entropy)
                    </p>
                </div>
            </div>
            
            <div class="grid-2">
                <div class="card">
                    <h2>📁 Trivy Filesystem Scan</h2>
                    <img src="trivy_fs_vulns.png" alt="Trivy FS Vulnerabilities">
                    <p style="margin-top: 15px;">
                        <strong>Summary:</strong> {sum(trivy_data.values())} total issues
                        (Critical: {trivy_data['CRITICAL']}, High: {trivy_data['HIGH']}, 
                        Medium: {trivy_data['MEDIUM']}, Low: {trivy_data['LOW']})
                    </p>
                </div>
                
                <div class="card">
                    <h2>🐳 Container Image Scan</h2>
                    <img src="container_vulns.png" alt="Container Vulnerabilities">
                    <p style="margin-top: 15px;">
                        <strong>Summary:</strong> {sum(container_data.values())} total issues
                        (Critical: {container_data['CRITICAL']}, High: {container_data['HIGH']}, 
                        Medium: {container_data['MEDIUM']}, Low: {container_data['LOW']})
                    </p>
                </div>
            </div>
            
            <div class="card">
                <h2>📊 Detailed Summary</h2>
                <img src="summary_table.png" alt="Summary Table" style="max-width: 100%;">
            </div>
        </div>
    </body>
    </html>
    """
    
    with open('dashboard/index.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("✅ Dashboard generated successfully!")
    print(f"📁 Dashboard location: dashboard/index.html")
    print(f"📊 Files created:")
    for file in os.listdir('dashboard'):
        print(f"   - {file}")

if __name__ == "__main__":
    try:
        create_visualizations()
    except Exception as e:
        print(f"❌ Error generating dashboard: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
