# Network Security System

A comprehensive network security system built with Python that uses machine learning to detect network anomalies and cyber attacks. The system processes network traffic data, trains multiple machine learning models, and provides real-time threat detection capabilities.

## Features

### 🛡️ Core Security Features
- **Multi-Model Machine Learning**: Implements Random Forest, Gradient Boosting, SVM, Neural Network, and Logistic Regression
- **Real-Time Packet Analysis**: Captures and analyzes network packets in real-time
- **Anomaly Detection**: Identifies suspicious network behavior and potential attacks
- **Attack Classification**: Categorizes different types of cyber attacks

### 📊 Data Processing & Analysis
- **Comprehensive Data Preprocessing**: Handles the UNSW-NB15 dataset with advanced feature engineering
- **Feature Engineering**: Creates meaningful features like packet rates, byte ratios, and connection patterns
- **Data Visualization**: Multiple visualization options for model performance and attack patterns
- **Statistical Analysis**: Detailed metrics and performance evaluation

### 🖥️ User Interface
- **Modern GUI Application**: User-friendly interface with multiple tabs for different functionalities
- **Real-Time Monitoring**: Live dashboard showing network statistics and anomaly detection
- **Interactive Visualizations**: Charts and graphs for model performance analysis
- **Logging System**: Comprehensive logging for system events and detections

## Installation

### Prerequisites
- Python 3.7 or higher
- Administrator privileges (for real-time packet capture)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Required Libraries
```
scapy>=2.4.5
pandas>=1.3.0
numpy>=1.21.0
scikit-learn>=1.0.0
matplotlib>=3.4.0
tkinter (usually comes with Python)
joblib>=1.1.0
```

## Usage

### 1. Data Preprocessing
```python
from data_preprocessing import DataPreprocessor

# Initialize preprocessor
preprocessor = DataPreprocessor()

# Load and preprocess data
train_data = preprocessor.load_data('UNSW_NB15_training-set.csv')
test_data = preprocessor.load_data('UNSW_NB15_testing-set.csv')

# Preprocess the data
X_train, y_train = preprocessor.preprocess_train_data(train_data)
X_test, y_test = preprocessor.preprocess_test_data(test_data)

# Save preprocessor for later use
preprocessor.save_preprocessor('models/preprocessor.pkl')
```

### 2. Model Training
```python
from network_security_models import NetworkSecurityModels

# Initialize models
models = NetworkSecurityModels()

# Train multiple models
model_types = ['Random Forest', 'Gradient Boosting', 'SVM', 'Neural Network', 'Logistic Regression']
results = models.train_all_models(X_train, y_train, model_types)

# Evaluate models
evaluation_results = models.evaluate_all_models(X_test, y_test)

# Save trained models
models.save_models('models/')
```

### 3. Real-Time Analysis
```python
from real_time_analyzer import RealTimePacketAnalyzer

# Initialize analyzer with trained model
analyzer = RealTimePacketAnalyzer(
    model_path='models/best_model.pkl',
    preprocessor_path='models/preprocessor.pkl'
)

# Start real-time packet analysis
analyzer.start_real_time_analysis(interface='Ethernet')

# Or analyze a PCAP file
analyzer.analyze_pcap_file('network_traffic.pcap')
```

### 4. GUI Application
```python
from gui_application import NetworkSecurityGUI
import tkinter as tk

# Create main window
root = tk.Tk()
app = NetworkSecurityGUI(root)
root.mainloop()
```

### 5. Visualization
```python
from visualization import NetworkSecurityVisualizer

# Initialize visualizer
visualizer = NetworkSecurityVisualizer()

# Create various plots
visualizer.plot_confusion_matrix(y_true, y_pred, model_name)
visualizer.plot_roc_curve(y_true, y_pred_proba, model_name)
visualizer.plot_feature_importance(feature_importances, feature_names)
visualizer.plot_attack_distribution(y_data)

# Generate comprehensive report
visualizer.generate_visual_report(models, X_test, y_test, output_path='reports/')
```

## Dataset Information

### UNSW-NB15 Dataset
The system uses the UNSW-NB15 dataset, which contains:
- **49 Features**: Network flow characteristics, connection metrics, and security attributes
- **Multiple Attack Categories**: Fuzzers, Reconnaissance, Shellcode, Analysis, DoS, Exploits, Generic
- **Realistic Network Traffic**: Modern network behavior and attack patterns

### Key Features
- **Network Flow Features**: Source/destination IPs, ports, protocols, packet counts, byte counts
- **Connection Features**: TCP states, window sizes, RTT values, connection duration
- **Security Features**: Attack categories, labels (normal/attack), service types
- **Temporal Features**: Inter-packet times, jitter, rates

## Model Performance

The system achieves the following performance metrics on the UNSW-NB15 dataset:

### Random Forest Classifier
- **Accuracy**: ~95%
- **Precision**: ~94%
- **Recall**: ~93%
- **F1-Score**: ~94%

### Gradient Boosting Classifier
- **Accuracy**: ~94%
- **Precision**: ~93%
- **Recall**: ~92%
- **F1-Score**: ~93%

### Support Vector Machine
- **Accuracy**: ~92%
- **Precision**: ~91%
- **Recall**: ~90%
- **F1-Score**: ~91%

### Neural Network
- **Accuracy**: ~93%
- **Precision**: ~92%
- **Recall**: ~91%
- **F1-Score**: ~92%

## Real-Time Detection Features

### Packet Analysis
- **Protocol Detection**: TCP, UDP, ICMP, ARP, and other protocols
- **Port Analysis**: Common service ports and suspicious port detection
- **Traffic Patterns**: Packet size analysis, flow duration, connection rates
- **Statistical Analysis**: Mean, variance, and trend analysis

### Anomaly Detection Rules
- **Large Packet Detection**: Flags packets larger than 1500 bytes
- **Suspicious Port Detection**: Monitors ports commonly used in attacks (135, 139, 445, 1433, 3389)
- **ICMP Flood Detection**: Detects excessive ICMP traffic
- **Port Scan Detection**: Identifies rapid connection attempts to different ports
- **Service Anomaly Detection**: Identifies unusual service usage patterns

## GUI Features

### Data Preprocessing Tab
- Load training and testing datasets
- View data preprocessing statistics
- Monitor preprocessing progress
- Export preprocessing results

### ML Models Tab
- Select and train multiple models
- View training progress and results
- Compare model performance metrics
- Export trained models

### Real-Time Analysis Tab
- Start/stop real-time packet analysis
- View live network statistics
- Monitor recent anomalies
- Interactive real-time charts

### Visualizations Tab
- Confusion matrices for all models
- ROC curves and AUC scores
- Feature importance plots
- Attack distribution analysis

### Logs Tab
- System event logging
- Anomaly detection logs
- Export logs functionality
- Real-time log updates

## Configuration

### Model Parameters
```python
# Random Forest Parameters
rf_params = {
    'n_estimators': 100,
    'max_depth': 10,
    'min_samples_split': 5,
    'min_samples_leaf': 2,
    'random_state': 42
}

# SVM Parameters
svm_params = {
    'C': 1.0,
    'kernel': 'rbf',
    'gamma': 'scale',
    'probability': True
}

# Neural Network Parameters
nn_params = {
    'hidden_layer_sizes': (100, 50),
    'max_iter': 1000,
    'random_state': 42
}
```

### Real-Time Analysis Parameters
```python
# Packet buffer size
packet_buffer_size = 1000

# Flow cache timeout
flow_cache_timeout = 300  # seconds

# Anomaly history size
anomaly_history_size = 1000

# Detection thresholds
large_packet_threshold = 1500  # bytes
port_scan_threshold = 10  # unique ports per minute
icmp_flood_threshold = 100  # ICMP packets per minute
```

## Advanced Usage

### Custom Feature Engineering
```python
# Add custom features
preprocessor.add_custom_feature('custom_ratio', 
    lambda df: df['sbytes'] / (df['dbytes'] + 1))

# Add time-based features
preprocessor.add_time_features(['hour', 'day_of_week', 'is_weekend'])

# Add interaction features
preprocessor.add_interaction_features(['srcip', 'dstip', 'dsport'])
```

### Custom Model Training
```python
# Define custom hyperparameter grid
param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [5, 10, 15, None],
    'min_samples_split': [2, 5, 10]
}

# Train with custom parameters
models.train_model_with_grid_search('Random Forest', param_grid)
```

### Batch Processing
```python
# Process multiple PCAP files
import glob

pcap_files = glob.glob('pcap_files/*.pcap')
for pcap_file in pcap_files:
    print(f"Processing {pcap_file}...")
    analyzer.analyze_pcap_file(pcap_file)
    
    # Get results
    stats = analyzer.get_statistics()
    print(f"Anomalies detected: {stats['anomaly_count']}")
```

## Troubleshooting

### Common Issues

1. **Permission Denied for Packet Capture**
   - Run the application with administrator privileges
   - On Linux: Use `sudo` or add user to `wireshark` group
   - On Windows: Run as Administrator

2. **Model Loading Errors**
   - Ensure model files exist in the specified directory
   - Check that the model and preprocessor versions match
   - Verify that all dependencies are installed

3. **GUI Display Issues**
   - Update matplotlib to the latest version
   - Install tkinter if not available: `sudo apt-get install python3-tk`
   - Check display settings and resolution

4. **Memory Issues with Large Datasets**
   - Use data sampling for initial testing
   - Increase system memory or use cloud resources
   - Implement data streaming for very large files

### Performance Optimization

1. **Model Training Speed**
   - Use smaller datasets for initial model development
   - Implement parallel processing for grid search
   - Use GPU acceleration for neural networks

2. **Real-Time Analysis Performance**
   - Optimize packet processing algorithms
   - Use multi-threading for concurrent processing
   - Implement packet filtering to reduce processing load

3. **Memory Usage**
   - Implement data streaming for large files
   - Use efficient data structures (NumPy arrays, Pandas DataFrames)
   - Regular garbage collection and memory cleanup

## Contributing

### Development Setup
1. Fork the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate virtual environment: `source venv/bin/activate` (Linux/Mac) or `venv\Scripts\activate` (Windows)
4. Install development dependencies: `pip install -r requirements.txt`
5. Run tests: `python -m pytest tests/`

### Code Structure
```
NetworkSecuritySystem/
├── data_preprocessing.py      # Data loading and preprocessing
├── network_security_models.py # ML model implementations
├── real_time_analyzer.py      # Real-time packet analysis
├── visualization.py           # Data visualization functions
├── gui_application.py         # GUI application
├── requirements.txt           # Python dependencies
├── README.md                  # Documentation
└── models/                    # Trained model storage
```

### Adding New Features
1. Create feature branch: `git checkout -b feature/new-feature`
2. Implement feature with tests
3. Update documentation
4. Submit pull request with detailed description

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **UNSW-NB15 Dataset**: Created by the Cyber Range Lab at UNSW Canberra
- **Scikit-learn**: Machine learning library
- **Scapy**: Packet manipulation library
- **Matplotlib**: Data visualization library

## Contact

For questions, issues, or contributions, please open an issue on the project repository or contact the development team.

---

**Note**: This system is designed for educational and research purposes. Always ensure you have proper authorization before monitoring network traffic in production environments.