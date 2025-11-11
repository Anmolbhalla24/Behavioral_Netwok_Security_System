#!/usr/bin/env python3
"""
Demo script to show how to use the Network Security System
and view analysis results
"""

import pandas as pd
import numpy as np
import argparse
from data_preprocessing import DataPreprocessor
import matplotlib.pyplot as plt
import seaborn as sns

def demo_data_analysis(train_file: str, test_file: str, train_sample_size: int = 5000):
    """Demonstrate data analysis with sample results"""
    print("🚀 Network Security System - Demo Analysis")
    print("=" * 50)
    
    # Step 1: Load and preprocess data
    print("\n📊 Step 1: Loading and Preprocessing Data")
    preprocessor = DataPreprocessor()
    
    # Load a sample of the data for quick demonstration
    print("Loading training data sample...")
    train_data = preprocessor.load_data(train_file, sample_size=train_sample_size)
    
    print("Loading testing data sample...")
    # Note: preprocess_test_data does not support sample_size; load full file for test
    test_data = preprocessor.load_data(test_file)
    
    # Preprocess the data
    print("Preprocessing training data...")
    X_train, y_train = preprocessor.preprocess_training_data(train_file, sample_size=train_sample_size)
    
    print("Preprocessing testing data...")
    X_test, y_test = preprocessor.preprocess_test_data(test_file)
    
    print(f"✅ Data preprocessing completed!")
    print(f"   Training data shape: {X_train.shape}")
    print(f"   Testing data shape: {X_test.shape}")
    print(f"   Attack distribution in training: {dict(y_train.value_counts())}")
    
    # Step 2: Simple model training (without hyperparameter tuning for speed)
    print("\n🤖 Step 2: Training Simple Models")
    # Note: For a quick demo, we train lightweight models directly below
    
    # Train a simple Random Forest (without GridSearchCV for speed)
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    
    # Quick Random Forest
    print("Training Random Forest...")
    rf_model = RandomForestClassifier(n_estimators=50, random_state=42)
    rf_model.fit(X_train, y_train)
    rf_pred = rf_model.predict(X_test)
    rf_accuracy = accuracy_score(y_test, rf_pred)
    
    print(f"✅ Random Forest Accuracy: {rf_accuracy:.4f}")
    
    # Quick Logistic Regression
    print("Training Logistic Regression...")
    lr_model = LogisticRegression(random_state=42, max_iter=1000)
    lr_model.fit(X_train, y_train)
    lr_pred = lr_model.predict(X_test)
    lr_accuracy = accuracy_score(y_test, lr_pred)
    
    print(f"✅ Logistic Regression Accuracy: {lr_accuracy:.4f}")
    
    # Step 3: Generate and display results
    print("\n📈 Step 3: Analysis Results")
    
    # Classification reports
    print("\n🎯 Random Forest Classification Report:")
    print(classification_report(y_test, rf_pred, target_names=['Normal', 'Attack']))
    
    print("\n🎯 Logistic Regression Classification Report:")
    print(classification_report(y_test, lr_pred, target_names=['Normal', 'Attack']))
    
    # Confusion matrices
    print("\n📊 Confusion Matrices:")
    rf_cm = confusion_matrix(y_test, rf_pred)
    lr_cm = confusion_matrix(y_test, lr_pred)
    
    print("Random Forest Confusion Matrix:")
    print(rf_cm)
    print("\nLogistic Regression Confusion Matrix:")
    print(lr_cm)
    
    # Step 4: Feature importance analysis
    print("\n🔍 Step 4: Feature Importance Analysis")
    feature_names = X_train.columns.tolist()
    rf_importance = rf_model.feature_importances_
    
    # Get top 10 most important features
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': rf_importance
    }).sort_values('importance', ascending=False)
    
    print("Top 10 Most Important Features:")
    for i, (_, row) in enumerate(importance_df.head(10).iterrows(), 1):
        print(f"{i:2d}. {row['feature']:25s} - {row['importance']:.4f}")
    
    # Step 5: Attack type analysis
    print("\n🚨 Step 5: Attack Type Analysis")
    if 'attack_cat' in test_data.columns:
        attack_counts = test_data['attack_cat'].value_counts()
        print("Attack Categories Distribution:")
        for attack_type, count in attack_counts.items():
            percentage = (count / len(test_data)) * 100
            print(f"   {attack_type:15s}: {count:6d} ({percentage:5.1f}%)")
    
    # Step 6: Network statistics
    print("\n🌐 Step 6: Network Traffic Statistics")
    if 'sbytes' in test_data.columns and 'dbytes' in test_data.columns:
        total_bytes = test_data['sbytes'] + test_data['dbytes']
        print(f"Average packet size: {total_bytes.mean():.2f} bytes")
        print(f"Max packet size: {total_bytes.max()} bytes")
        print(f"Min packet size: {total_bytes.min()} bytes")
    
    if 'dur' in test_data.columns:
        print(f"Average connection duration: {test_data['dur'].mean():.2f} seconds")
        print(f"Max connection duration: {test_data['dur'].max():.2f} seconds")
    
    # Step 7: Save results
    print("\n💾 Step 7: Saving Results")
    
    # Save model performance summary
    results_summary = pd.DataFrame({
        'Model': ['Random Forest', 'Logistic Regression'],
        'Accuracy': [rf_accuracy, lr_accuracy],
        'Training_Samples': [len(X_train), len(X_train)],
        'Test_Samples': [len(X_test), len(X_test)]
    })
    
    results_summary.to_csv('demo_results_summary.csv', index=False)
    importance_df.head(10).to_csv('demo_feature_importance.csv', index=False)
    
    print("✅ Results saved to:")
    print("   - demo_results_summary.csv")
    print("   - demo_feature_importance.csv")
    
    print("\n🎉 Demo Analysis Complete!")
    print("=" * 50)
    print("You can now:")
    print("1. Open the CSV files to see detailed results")
    print("2. Use the GUI application for interactive analysis")
    print("3. Run the full pipeline with larger datasets")
    print("4. Use the trained models for real-time prediction")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Demo analysis runner")
    parser.add_argument("--train-file", default="data/UNSW_NB15_training-set.csv", help="Path to training CSV")
    parser.add_argument("--test-file", default="data/UNSW_NB15_testing-set.csv", help="Path to testing CSV")
    parser.add_argument("--train-sample-size", type=int, default=5000, help="Training sample size for fast runs")
    args = parser.parse_args()

    demo_data_analysis(args.train_file, args.test_file, args.train_sample_size)