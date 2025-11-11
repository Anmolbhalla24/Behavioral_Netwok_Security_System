#!/usr/bin/env python3
"""
Network Security System - Main Application Runner
This script provides a command-line interface to run different components of the network security system.
"""

import argparse
import sys
import os
import logging
from datetime import datetime

def setup_logging(log_level='INFO'):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'network_security_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def run_data_preprocessing(train_file, test_file, output_dir):
    """Run data preprocessing"""
    try:
        from data_preprocessing import DataPreprocessor
        
        logging.info("Starting data preprocessing...")
        
        # Initialize preprocessor
        preprocessor = DataPreprocessor()
        
        # Load data
        logging.info(f"Loading training data from {train_file}")
        train_data = preprocessor.load_data(train_file)
        
        logging.info(f"Loading testing data from {test_file}")
        test_data = preprocessor.load_data(test_file)
        
        # Preprocess data
        logging.info("Preprocessing training data...")
        X_train, y_train = preprocessor.preprocess_training_data(train_file)
        
        logging.info("Preprocessing testing data...")
        X_test, y_test = preprocessor.preprocess_test_data(test_file)
        
        # Save preprocessor
        os.makedirs(output_dir, exist_ok=True)
        preprocessor_path = os.path.join(output_dir, 'preprocessor.pkl')
        preprocessor.save_preprocessor(preprocessor_path)
        
        logging.info(f"Data preprocessing completed. Preprocessor saved to {preprocessor_path}")
        logging.info(f"Training data shape: {X_train.shape}")
        logging.info(f"Testing data shape: {X_test.shape}")
        
        return X_train, y_train, X_test, y_test
        
    except Exception as e:
        logging.error(f"Error in data preprocessing: {e}")
        sys.exit(1)

def run_model_training(X_train, y_train, models_to_train, output_dir):
    """Run model training"""
    try:
        from network_security_models import NetworkSecurityModels
        
        logging.info("Starting model training...")
        
        # Initialize models
        models = NetworkSecurityModels()
        
        # Train models
        results = models.train_all_models(X_train, y_train, models_to_train)
        
        # Save models
        os.makedirs(output_dir, exist_ok=True)
        models.save_models(output_dir)
        
        logging.info("Model training completed.")
        for model_name, metrics in results.items():
            logging.info(f"{model_name} - Training Accuracy: {metrics.get('train_accuracy', 'N/A'):.4f}")
        
        return models
        
    except Exception as e:
        logging.error(f"Error in model training: {e}")
        sys.exit(1)

def run_model_evaluation(models, X_test, y_test):
    """Run model evaluation"""
    try:
        logging.info("Starting model evaluation...")
        
        # Evaluate models
        evaluation_results = models.evaluate_all_models(X_test, y_test)
        
        logging.info("Model evaluation completed.")
        for model_name, metrics in evaluation_results.items():
            logging.info(f"{model_name}:")
            for metric, value in metrics.items():
                logging.info(f"  {metric}: {value:.4f}")
        
        return evaluation_results
        
    except Exception as e:
        logging.error(f"Error in model evaluation: {e}")
        sys.exit(1)

def run_real_time_analysis(model_path, preprocessor_path, interface, duration):
    """Run real-time packet analysis"""
    try:
        from real_time_analyzer import RealTimePacketAnalyzer
        
        logging.info("Starting real-time packet analysis...")
        
        # Initialize analyzer
        analyzer = RealTimePacketAnalyzer(model_path, preprocessor_path)
        
        # Start analysis
        analyzer.start_real_time_analysis(interface, duration)
        
    except KeyboardInterrupt:
        logging.info("Real-time analysis stopped by user.")
    except Exception as e:
        logging.error(f"Error in real-time analysis: {e}")
        sys.exit(1)

def run_gui():
    """Run the GUI application"""
    try:
        import tkinter as tk
        from gui_application import NetworkSecurityGUI
        
        logging.info("Starting GUI application...")
        
        # Create main window
        root = tk.Tk()
        app = NetworkSecurityGUI(root)
        
        logging.info("GUI application started successfully.")
        
        # Run the GUI
        root.mainloop()
        
    except Exception as e:
        logging.error(f"Error in GUI application: {e}")
        sys.exit(1)

def run_visualization(models, X_test, y_test, output_dir):
    """Generate visualizations"""
    try:
        from visualization import NetworkSecurityVisualizer
        
        logging.info("Generating visualizations...")
        
        # Initialize visualizer
        visualizer = NetworkSecurityVisualizer()
        
        # Generate comprehensive report
        os.makedirs(output_dir, exist_ok=True)
        visualizer.generate_visual_report(models, X_test, y_test, output_dir)
        
        logging.info(f"Visualizations saved to {output_dir}")
        
    except Exception as e:
        logging.error(f"Error generating visualizations: {e}")
        sys.exit(1)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Network Security System')
    parser.add_argument('--mode', choices=['preprocess', 'train', 'evaluate', 'realtime', 'gui', 'full', 'visualize'], 
                       default='gui', help='Operation mode')
    parser.add_argument('--train-file', default='UNSW_NB15_training-set.csv', 
                       help='Path to training data file')
    parser.add_argument('--test-file', default='UNSW_NB15_testing-set.csv', 
                       help='Path to testing data file')
    parser.add_argument('--models-dir', default='models', 
                       help='Directory for model storage')
    parser.add_argument('--reports-dir', default='reports', 
                       help='Directory for reports and visualizations')
    parser.add_argument('--models-to-train', nargs='+', 
                       choices=['Random Forest', 'Gradient Boosting', 'SVM', 'Neural Network', 'Logistic Regression'],
                       default=['Random Forest', 'Gradient Boosting', 'SVM', 'Neural Network'],
                       help='Models to train')
    parser.add_argument('--interface', default='Ethernet', 
                       help='Network interface for real-time analysis')
    parser.add_argument('--duration', type=int, default=None, 
                       help='Duration for real-time analysis (seconds)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Logging level')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    logging.info("Network Security System started")
    logging.info(f"Mode: {args.mode}")
    
    try:
        if args.mode == 'preprocess':
            # Run only data preprocessing
            run_data_preprocessing(args.train_file, args.test_file, args.models_dir)
            
        elif args.mode == 'train':
            # Run preprocessing and training
            X_train, y_train, X_test, y_test = run_data_preprocessing(
                args.train_file, args.test_file, args.models_dir)
            models = run_model_training(X_train, y_train, args.models_to_train, args.models_dir)
            
        elif args.mode == 'evaluate':
            # Run full pipeline and evaluation
            X_train, y_train, X_test, y_test = run_data_preprocessing(
                args.train_file, args.test_file, args.models_dir)
            models = run_model_training(X_train, y_train, args.models_to_train, args.models_dir)
            evaluation_results = run_model_evaluation(models, X_test, y_test)
            
        elif args.mode == 'realtime':
            # Run real-time analysis
            model_path = os.path.join(args.models_dir, 'best_model.pkl')
            preprocessor_path = os.path.join(args.models_dir, 'preprocessor.pkl')
            
            if not os.path.exists(model_path) or not os.path.exists(preprocessor_path):
                logging.error("Model or preprocessor not found. Please run training first.")
                sys.exit(1)
            
            run_real_time_analysis(model_path, preprocessor_path, args.interface, args.duration)
            
        elif args.mode == 'gui':
            # Run GUI application
            run_gui()
            
        elif args.mode == 'full':
            # Run complete pipeline
            logging.info("Running complete pipeline...")
            
            # Data preprocessing
            X_train, y_train, X_test, y_test = run_data_preprocessing(
                args.train_file, args.test_file, args.models_dir)
            
            # Model training
            models = run_model_training(X_train, y_train, args.models_to_train, args.models_dir)
            
            # Model evaluation
            evaluation_results = run_model_evaluation(models, X_test, y_test)
            
            # Generate visualizations
            run_visualization(models, X_test, y_test, args.reports_dir)
            
            logging.info("Complete pipeline finished successfully!")
            
        elif args.mode == 'visualize':
            # Generate visualizations only
            from network_security_models import NetworkSecurityModels
            
            # Load existing models
            models = NetworkSecurityModels()
            models.load_models(args.models_dir)
            
            # Load test data
            from data_preprocessing import DataPreprocessor
            preprocessor = DataPreprocessor()
            test_data = preprocessor.load_data(args.test_file)
            X_test, y_test = preprocessor.preprocess_test_data(test_data)
            
            # Generate visualizations
            run_visualization(models, X_test, y_test, args.reports_dir)
            
    except KeyboardInterrupt:
        logging.info("Application interrupted by user.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
    
    logging.info("Network Security System finished")

if __name__ == "__main__":
    main()