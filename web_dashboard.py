#!/usr/bin/env python3
"""
Simple Web Dashboard for Network Security System
Provides a web interface to view analysis results
"""

from flask import Flask, render_template, jsonify, request
import pandas as pd
import json
import os
from datetime import datetime

app = Flask(__name__)

# Load analysis results
def load_results():
    """Load analysis results from CSV files"""
    results = {}
    
    # Load model performance results
    if os.path.exists('demo_results_summary.csv'):
        results['model_performance'] = pd.read_csv('demo_results_summary.csv').to_dict('records')
    
    # Load feature importance
    if os.path.exists('demo_feature_importance.csv'):
        results['feature_importance'] = pd.read_csv('demo_feature_importance.csv').to_dict('records')
    
    # Load system info
    results['system_info'] = {
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'models_trained': len(results.get('model_performance', [])),
        'total_features': len(results.get('feature_importance', []))
    }
    
    return results

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/results')
def get_results():
    """API endpoint for analysis results"""
    results = load_results()
    return jsonify(results)

@app.route('/api/network-stats')
def get_network_stats():
    """API endpoint for network statistics"""
    # Mock network statistics (replace with real data)
    stats = {
        'total_connections': 175341,
        'attack_detected': 119341,
        'normal_traffic': 56000,
        'attack_rate': 68.0,
        'top_attack_types': [
            {'type': 'DoS', 'count': 45000, 'percentage': 25.7},
            {'type': 'Exploits', 'count': 38000, 'percentage': 21.7},
            {'type': 'Fuzzers', 'count': 22000, 'percentage': 12.6},
            {'type': 'Reconnaissance', 'count': 14341, 'percentage': 8.2}
        ]
    }
    return jsonify(stats)

@app.route('/api/model-comparison')
def get_model_comparison():
    """API endpoint for model comparison"""
    comparison = {
        'models': [
            {
                'name': 'Random Forest',
                'accuracy': 70.1,
                'precision': 68.5,
                'recall': 99.7,
                'f1_score': 81.3,
                'training_time': '2.3s'
            },
            {
                'name': 'Logistic Regression', 
                'accuracy': 68.2,
                'precision': 68.0,
                'recall': 100.0,
                'f1_score': 80.9,
                'training_time': '1.1s'
            }
        ]
    }
    return jsonify(comparison)

# Create templates directory and HTML file
templates_dir = 'templates'
os.makedirs(templates_dir, exist_ok=True)

html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .chart-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }
        .attack-high { color: #e74c3c; }
        .attack-medium { color: #f39c12; }
        .attack-low { color: #27ae60; }
        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Network Security Dashboard</h1>
        <p>Real-time network security analysis and threat detection</p>
    </div>

    <div class="stats-grid" id="stats-grid">
        <div class="loading">Loading statistics...</div>
    </div>

    <div class="chart-grid">
        <div class="chart-container">
            <h3>Attack Distribution</h3>
            <canvas id="attackChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h3>Model Performance Comparison</h3>
            <canvas id="modelChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h3>Feature Importance</h3>
            <canvas id="featureChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h3>Network Traffic Overview</h3>
            <canvas id="trafficChart"></canvas>
        </div>
    </div>

    <script>
        // Load and display statistics
        async function loadStats() {
            try {
                const response = await fetch('/api/network-stats');
                const data = await response.json();
                
                const statsGrid = document.getElementById('stats-grid');
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-number">${data.total_connections.toLocaleString()}</div>
                        <div class="stat-label">Total Connections</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number attack-high">${data.attack_detected.toLocaleString()}</div>
                        <div class="stat-label">Attacks Detected</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number attack-low">${data.normal_traffic.toLocaleString()}</div>
                        <div class="stat-label">Normal Traffic</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number attack-medium">${data.attack_rate}%</div>
                        <div class="stat-label">Attack Rate</div>
                    </div>
                `;
                
                // Attack distribution chart
                const attackCtx = document.getElementById('attackChart').getContext('2d');
                new Chart(attackCtx, {
                    type: 'doughnut',
                    data: {
                        labels: data.top_attack_types.map(item => item.type),
                        datasets: [{
                            data: data.top_attack_types.map(item => item.count),
                            backgroundColor: ['#e74c3c', '#f39c12', '#f1c40f', '#27ae60']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'bottom' }
                        }
                    }
                });
                
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }

        // Load model comparison
        async function loadModelComparison() {
            try {
                const response = await fetch('/api/model-comparison');
                const data = await response.json();
                
                const modelCtx = document.getElementById('modelChart').getContext('2d');
                new Chart(modelCtx, {
                    type: 'radar',
                    data: {
                        labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score'],
                        datasets: data.models.map((model, index) => ({
                            label: model.name,
                            data: [model.accuracy, model.precision, model.recall, model.f1_score],
                            borderColor: index === 0 ? '#3498db' : '#e74c3c',
                            backgroundColor: index === 0 ? 'rgba(52, 152, 219, 0.2)' : 'rgba(231, 76, 60, 0.2)'
                        }))
                    },
                    options: {
                        responsive: true,
                        scales: {
                            r: {
                                beginAtZero: true,
                                max: 100
                            }
                        }
                    }
                });
                
            } catch (error) {
                console.error('Error loading model comparison:', error);
            }
        }

        // Load feature importance
        async function loadFeatureImportance() {
            try {
                const response = await fetch('/api/results');
                const data = await response.json();
                
                if (data.feature_importance) {
                    const topFeatures = data.feature_importance.slice(0, 10);
                    
                    const featureCtx = document.getElementById('featureChart').getContext('2d');
                    new Chart(featureCtx, {
                        type: 'bar',
                        data: {
                            labels: topFeatures.map(item => item.feature),
                            datasets: [{
                                label: 'Importance',
                                data: topFeatures.map(item => item.importance),
                                backgroundColor: '#3498db'
                            }]
                        },
                        options: {
                            responsive: true,
                            indexAxis: 'y',
                            plugins: {
                                legend: { display: false }
                            }
                        }
                    });
                }
                
            } catch (error) {
                console.error('Error loading feature importance:', error);
            }
        }

        // Load traffic overview
        async function loadTrafficOverview() {
            try {
                const response = await fetch('/api/network-stats');
                const data = await response.json();
                
                const trafficCtx = document.getElementById('trafficChart').getContext('2d');
                new Chart(trafficCtx, {
                    type: 'line',
                    data: {
                        labels: ['Normal', 'DoS', 'Exploits', 'Fuzzers', 'Reconnaissance'],
                        datasets: [{
                            label: 'Connection Count',
                            data: [data.normal_traffic, 45000, 38000, 22000, 14341],
                            borderColor: '#27ae60',
                            backgroundColor: 'rgba(39, 174, 96, 0.1)',
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { display: false }
                        }
                    }
                });
                
            } catch (error) {
                console.error('Error loading traffic overview:', error);
            }
        }

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            loadStats();
            loadModelComparison();
            loadFeatureImportance();
            loadTrafficOverview();
        });
    </script>
</body>
</html>'''

# Write the HTML template
with open(os.path.join(templates_dir, 'dashboard.html'), 'w', encoding='utf-8') as f:
    f.write(html_template)

if __name__ == '__main__':
    print("🌐 Starting Network Security Web Dashboard...")
    print("📊 Dashboard will be available at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop the server")
    
    app.run(host='0.0.0.0', port=5000, debug=False)