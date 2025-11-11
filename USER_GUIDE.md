# 🛡️ Network Security System - User Guide

## Overview
This is a **desktop GUI application** (not a web app) that provides network security analysis using machine learning. The application analyzes network traffic data to detect cyber attacks and intrusions.

## 🚀 Quick Start

### 1. Launch the Application
```bash
python main.py --mode gui
```
**Note**: This opens a desktop window, not a web browser.

### 2. System Requirements
- Python 3.7+
- Windows/Mac/Linux
- 4GB+ RAM recommended for large datasets

## 📋 Application Interface

The GUI has **5 main tabs**:

### 1. 📊 Data Preprocessing Tab
- **Purpose**: Load and prepare network traffic data
- **What it does**: 
  - Cleans raw network data
  - Encodes categorical features (protocols, services, states)
  - Creates new security-focused features
  - Scales data for machine learning
- **Files**: Uses `data/UNSW_NB15_training-set.csv` and `data/UNSW_NB15_testing-set.csv`

### 2. 🤖 ML Models Tab
- **Purpose**: Train and evaluate machine learning models
- **Available Models**:
  - Random Forest Classifier
  - Gradient Boosting
  - Support Vector Machine (SVM)
  - Neural Network
  - Logistic Regression
- **Outputs**: Model accuracy, precision, recall, F1-scores

### 3. ⚡ Real-Time Analysis Tab
- **Purpose**: Monitor live network traffic
- **Features**:
  - Live packet capture simulation
  - Real-time attack detection
  - Traffic visualization
  - Alert generation

### 4. 📈 Visualizations Tab
- **Purpose**: Create charts and graphs
- **Available Visualizations**:
  - Attack distribution pie charts
  - Network traffic time series
  - Feature importance plots
  - Model performance comparisons
  - Confusion matrices

### 5. 📝 Logs Tab
- **Purpose**: View system activity and errors
- **Shows**: Processing status, error messages, completion times

## 📁 Data Files

### Training Data
- **File**: `data/UNSW_NB15_training-set.csv`
- **Size**: ~175,000 network connections
- **Features**: 45 network characteristics
- **Labels**: Normal (0) vs Attack (1)

### Testing Data
- **File**: `data/UNSW_NB15_testing-set.csv` 
- **Size**: ~82,000 network connections
- **Same format as training data

### Attack Types in Dataset
- **Normal**: Legitimate network traffic
- **DoS**: Denial of Service attacks
- **Exploits**: System vulnerability exploits
- **Fuzzers**: Protocol fuzzing attacks
- **Reconnaissance**: Network scanning
- **Generic**: Other attack types

## 🔧 Command Line Usage

### GUI Mode (Desktop Application)
```bash
python main.py --mode gui
```

### Complete Pipeline (All Steps)
```bash
python main.py --mode full \
  --train-file data/UNSW_NB15_training-set.csv \
  --test-file data/UNSW_NB15_testing-set.csv \
  --models-dir models \
  --reports-dir reports
```

### Data Preprocessing Only
```bash
python main.py --mode preprocess \
  --train-file data/UNSW_NB15_training-set.csv \
  --test-file data/UNSW_NB15_testing-set.csv \
  --models-dir models
```

### Model Training Only
```bash
python main.py --mode train \
  --train-file data/UNSW_NB15_training-set.csv \
  --test-file data/UNSW_NB15_testing-set.csv \
  --models-dir models \
  --models-to-train "Random Forest" "Logistic Regression"
```

### Real-Time Monitoring
```bash
python main.py --mode realtime --duration 60
```

### Generate Visualizations
```bash
python main.py --mode visualize \
  --train-file data/UNSW_NB15_training-set.csv \
  --test-file data/UNSW_NB15_testing-set.csv \
  --reports-dir reports
```

## 📊 Understanding Results

### Model Performance Metrics
- **Accuracy**: Percentage of correct predictions
- **Precision**: Of detected attacks, how many were actually attacks
- **Recall**: Of actual attacks, how many were detected
- **F1-Score**: Balanced measure of precision and recall

### Feature Importance
Shows which network characteristics are most important for detecting attacks:
1. **Connection ID** - Unique connection identifier
2. **Attack Category** - Type of attack (if labeled)
3. **Connection State** - TCP connection state (FIN, CON, INT)
4. **Source Mean** - Average source packet size
5. **Connection Rate** - Packets per second

### Network Statistics
- **Packet Sizes**: Average, min, max bytes per connection
- **Duration**: Connection length in seconds
- **Protocols**: TCP, UDP, ICMP distribution
- **Services**: HTTP, FTP, SMTP, DNS usage

## 🎯 Typical Use Cases

### 1. Network Security Analysis
```bash
# Analyze historical network data
python main.py --mode full --train-file your_data.csv --test-file your_test.csv
```

### 2. Model Comparison
```bash
# Train specific models and compare performance
python main.py --mode train --models-to-train "Random Forest" "SVM" "Neural Network"
```

### 3. Real-Time Monitoring
```bash
# Monitor network for 5 minutes
python main.py --mode realtime --duration 300
```

### 4. Custom Visualization
```bash
# Create custom charts and reports
python main.py --mode visualize --reports-dir my_reports
```

## 🚨 Common Issues and Solutions

### Issue: "No module named 'xyz'"
**Solution**: Install requirements
```bash
pip install -r requirements.txt
```

### Issue: "File not found"
**Solution**: Check data files are in the `data/` folder

### Issue: "Out of memory"
**Solution**: Use smaller dataset or increase system RAM

### Issue: "Model training failed"
**Solution**: Check data preprocessing completed successfully first

## 📁 Output Files

### Models Directory (`models/`)
- `preprocessor.pkl` - Data preprocessing pipeline
- `best_model_info.pkl` - Best performing model information
- Individual model files (when training succeeds)

### Reports Directory (`reports/`)
- Performance metrics CSV files
- Visualization plots and charts
- Analysis summaries

### Demo Files (Created by demo script)
- `demo_results_summary.csv` - Model performance summary
- `demo_feature_importance.csv` - Feature importance ranking

## 🎓 Learning More

### Key Concepts
- **Network Traffic Analysis**: Examining packet headers and metadata
- **Feature Engineering**: Creating meaningful characteristics from raw data
- **Machine Learning**: Training algorithms to recognize attack patterns
- **Real-Time Detection**: Identifying threats as they occur

### Next Steps
1. Run the GUI application to explore the interface
2. Try the demo analysis script: `python demo_analysis.py`
3. Experiment with different machine learning models
4. Create custom visualizations for your specific needs
5. Set up real-time monitoring for your network

---

**💡 Tip**: Start with the GUI mode to get familiar with the system, then use command-line modes for specific tasks or automation.

**Need Help?** Check the log files (`network_security_*.log`) for detailed error messages and system status.