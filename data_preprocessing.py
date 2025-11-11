import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os

class DataPreprocessor:
    def __init__(self):
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.feature_names = None
        
    def load_data(self, file_path, sample_size=None):
        """Load and preprocess the UNSW-NB15 dataset"""
        print(f"Loading data from {file_path}...")
        
        # Load data with proper handling for large files
        if sample_size:
            df = pd.read_csv(file_path, nrows=sample_size)
        else:
            df = pd.read_csv(file_path)
            
        print(f"Data loaded successfully. Shape: {df.shape}")
        return df
    
    def clean_data(self, df):
        """Clean and preprocess the data"""
        print("Cleaning data...")
        
        # Remove rows with missing values
        initial_rows = len(df)
        df = df.dropna()
        print(f"Removed {initial_rows - len(df)} rows with missing values")
        
        # Handle infinite values
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna()
        
        # Remove duplicates
        df = df.drop_duplicates()
        
        print(f"Data cleaned. Final shape: {df.shape}")
        return df
    
    def encode_categorical_features(self, df, categorical_columns):
        """Encode categorical features using LabelEncoder"""
        print("Encoding categorical features...")
        
        for col in categorical_columns:
            if col in df.columns:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                self.label_encoders[col] = le
                print(f"Encoded {col}: {len(le.classes_)} unique values")
        
        return df
    
    def create_feature_engineering(self, df):
        """Create new engineered features"""
        print("Creating engineered features...")
        
        # Traffic volume features
        df['total_bytes'] = df['sbytes'] + df['dbytes']
        df['total_packets'] = df['spkts'] + df['dpkts']
        
        # Rate features
        if 'dur' in df.columns and df['dur'].sum() > 0:
            df['bytes_per_second'] = df['total_bytes'] / (df['dur'] + 1e-6)
            df['packets_per_second'] = df['total_packets'] / (df['dur'] + 1e-6)
        
        # Ratio features
        df['byte_ratio'] = df['sbytes'] / (df['dbytes'] + 1e-6)
        df['packet_ratio'] = df['spkts'] / (df['dpkts'] + 1e-6)
        
        # Connection state features
        if 'state' in df.columns:
            state_counts = df['state'].value_counts()
            df['state_rarity'] = df['state'].map(state_counts) / len(df)
        
        # Service rarity
        if 'service' in df.columns:
            service_counts = df['service'].value_counts()
            df['service_rarity'] = df['service'].map(service_counts) / len(df)
        
        print("Feature engineering completed")
        return df
    
    def select_features(self, df, target_column='label', correlation_threshold=0.95):
        """Select relevant features for training"""
        print("Selecting features...")
        
        # Separate features and target
        if target_column in df.columns:
            X = df.drop(columns=[target_column])
            y = df[target_column]
        else:
            X = df
            y = None
        
        # Remove features with very low variance
        low_variance_features = []
        for col in X.select_dtypes(include=[np.number]).columns:
            if X[col].var() < 0.01:
                low_variance_features.append(col)
        
        X = X.drop(columns=low_variance_features)
        print(f"Removed {len(low_variance_features)} low variance features")
        
        # Remove highly correlated features
        numeric_features = X.select_dtypes(include=[np.number]).columns
        corr_matrix = X[numeric_features].corr().abs()
        
        upper_triangle = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
        high_corr_features = [column for column in upper_triangle.columns 
                               if any(upper_triangle[column] > correlation_threshold)]
        
        X = X.drop(columns=high_corr_features)
        print(f"Removed {len(high_corr_features)} highly correlated features")
        
        self.feature_names = X.columns.tolist()
        print(f"Selected {len(self.feature_names)} features")
        
        if y is not None:
            return X, y
        return X
    
    def scale_features(self, X, fit=True):
        """Scale features using StandardScaler"""
        print("Scaling features...")
        
        numeric_columns = X.select_dtypes(include=[np.number]).columns
        
        if fit:
            X_scaled = self.scaler.fit_transform(X[numeric_columns])
        else:
            X_scaled = self.scaler.transform(X[numeric_columns])
        
        X_scaled_df = pd.DataFrame(X_scaled, columns=numeric_columns, index=X.index)
        
        # Keep non-numeric columns as they are
        non_numeric_columns = X.select_dtypes(exclude=[np.number]).columns
        if len(non_numeric_columns) > 0:
            X_scaled_df[non_numeric_columns] = X[non_numeric_columns]
        
        return X_scaled_df
    
    def preprocess_training_data(self, train_file, sample_size=None):
        """Complete preprocessing pipeline for training data"""
        print("Starting complete preprocessing pipeline...")
        
        # Load data
        df = self.load_data(train_file, sample_size)
        
        # Clean data
        df = self.clean_data(df)
        
        # Define categorical columns
        categorical_columns = ['proto', 'service', 'state', 'attack_cat']
        
        # Encode categorical features
        df = self.encode_categorical_features(df, categorical_columns)
        
        # Feature engineering
        df = self.create_feature_engineering(df)
        
        # Select features
        X, y = self.select_features(df, target_column='label')
        
        # Scale features
        X_scaled = self.scale_features(X, fit=True)
        
        print("Preprocessing completed successfully!")
        print(f"Final dataset shape: {X_scaled.shape}")
        print(f"Target distribution: {y.value_counts().to_dict()}")
        
        return X_scaled, y
    
    def preprocess_test_data(self, test_file):
        """Preprocessing pipeline for test data"""
        print("Preprocessing test data...")
        
        # Load data
        df = self.load_data(test_file)
        
        # Clean data
        df = self.clean_data(df)
        
        # Encode categorical features using existing encoders
        categorical_columns = ['proto', 'service', 'state', 'attack_cat']
        for col in categorical_columns:
            if col in df.columns and col in self.label_encoders:
                # Handle unseen categories
                df[col] = df[col].astype(str)
                mask = df[col].isin(self.label_encoders[col].classes_)
                df.loc[~mask, col] = 'unknown'
                
                if 'unknown' not in self.label_encoders[col].classes_:
                    self.label_encoders[col].classes_ = np.append(
                        self.label_encoders[col].classes_, 'unknown'
                    )
                
                df[col] = self.label_encoders[col].transform(df[col])
        
        # Feature engineering
        df = self.create_feature_engineering(df)
        
        # Select features using saved feature names
        if self.feature_names:
            X = df[self.feature_names]
        else:
            X = df.drop(columns=['label'] if 'label' in df.columns else [])
        
        # Scale features
        X_scaled = self.scale_features(X, fit=False)
        
        # Extract target if present
        y = df['label'] if 'label' in df.columns else None
        
        return X_scaled, y
    
    def save_preprocessor(self, filepath):
        """Save the preprocessor state"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            'label_encoders': self.label_encoders,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }, filepath)
        print(f"Preprocessor saved to {filepath}")
    
    def load_preprocessor(self, filepath):
        """Load the preprocessor state"""
        state = joblib.load(filepath)
        self.label_encoders = state['label_encoders']
        self.scaler = state['scaler']
        self.feature_names = state['feature_names']
        print(f"Preprocessor loaded from {filepath}")

def main():
    """Example usage"""
    preprocessor = DataPreprocessor()
    
    # Process training data
    X_train, y_train = preprocessor.preprocess_training_data(
        'data/UNSW_NB15_training-set.csv',
        sample_size=100000  # Use sample for testing
    )
    
    # Process test data
    X_test, y_test = preprocessor.preprocess_test_data(
        'data/UNSW_NB15_testing-set.csv'
    )
    
    # Save preprocessor
    preprocessor.save_preprocessor('models/preprocessor.pkl')
    
    # Split training data for validation
    X_train_split, X_val_split, y_train_split, y_val_split = train_test_split(
        X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
    )
    
    print(f"Training set: {X_train_split.shape}")
    print(f"Validation set: {X_val_split.shape}")
    print(f"Test set: {X_test.shape}")
    
    return X_train_split, X_val_split, y_train_split, y_val_split, X_test, y_test

if __name__ == "__main__":
    main()