import json
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
from datetime import datetime
import os

# Wczytaj dane z różnych raportów
def load_bandit_metrics():
    with open('metrics/bandit-report.json', 'r') as f:
        data = json.load(f)
    return {
        'secrets': data.get('results', {}).get('SEVERITY', {}),
        'vulnerabilities': len(data.get('results', []))
    }

def load_trivy_metrics():
    with open('metrics/trivy-report.json', 'r') as f:
        data = json.load(f)
    
    vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', 'UNKNOWN')
            if severity in vuln_counts:
                vuln_counts[severity] += 1
    
    return vuln_counts

def create_visualizations():
    # 1. Wykres słupkowy dla podatności Trivy
    trivy_data = load_trivy_metrics()
    
    fig, ax = plt.subplots(figsize=(10, 6))
    severities = list(trivy_data.keys())
    counts = list(trivy_data.values())
    
    colors = {'CRITICAL': 'darkred', 'HIGH': 'red', 
              'MEDIUM': 'orange', 'LOW': 'yellow'}
    bar_colors = [colors.get(s, 'blue') for s in severities]
    
    bars = ax.bar(severities, counts, color=bar_colors)
    ax.set_title('Security Vulnerabilities by Severity')
    ax.set_ylabel('Count')
    
    # Dodaj wartości na słupkach
    for bar, count in zip(bars, counts):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                   str(count), ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig('dashboard/trivy_vulns.png')
    
    # 2. Interactive plot z Plotly dla trendów (jeśli masz historyczne dane)
    # Załaduj poprzednie metryki z artifactu lub GitHub Releases
    try:
        # Symulacja danych historycznych
        dates = pd.date_range(end=datetime.now(), periods=10, freq='W')
        vuln_trend = pd.DataFrame({
            'date': dates,
            'critical': np.random.randint(0, 5, 10),
            'high': np.random.randint(1, 10, 10),
            'medium': np.random.randint(5, 20, 10)
        })
        
        fig = px.line(vuln_trend, x='date', y=['critical', 'high', 'medium'],
                     title='Vulnerability Trends Over Time',
                     labels={'value': 'Number of Vulnerabilities', 
                            'variable': 'Severity'})
        fig.write_html('dashboard/vuln_trend.html')
    except:
        pass
    
    # 3. Generuj główny dashboard HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Metrics Dashboard</title>
        <style>
            body {{ font-family: Arial; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: auto; }}
            .card {{ background: white; border-radius: 8px; padding: 20px; 
                    margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 20px; }}
            h1 {{ color: #333; }}
            .metric {{ font-size: 24px; font-weight: bold; color: #007bff; }}
            .timestamp {{ color: #666; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Security Metrics Dashboard</h1>
            <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            
            <div class="grid">
                <div class="card">
                    <h2>🐍 Bandit SAST Results</h2>
                    <div class="metric">Vulnerabilities: {load_bandit_metrics()['vulnerabilities']}</div>
                </div>
                
                <div class="card">
                    <h2>🐳 Trivy Vulnerabilities</h2>
                    <img src="trivy_vulns.png" style="width: 100%;">
                </div>
            </div>
            
            <div class="card">
                <h2>📈 Vulnerability Trends</h2>
                <iframe src="vuln_trend.html" width="100%" height="500px" frameborder="0"></iframe>
            </div>
        </div>
    </body>
    </html>
    """
    
    os.makedirs('dashboard', exist_ok=True)
    with open('dashboard/index.html', 'w') as f:
        f.write(html_content)

if __name__ == "__main__":
    create_visualizations()
