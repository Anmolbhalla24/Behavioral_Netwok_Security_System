import os
import joblib
from typing import Dict, List, Optional

import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


class NetworkSecurityModels:
    """Minimal models manager for training, evaluating, and persisting classifiers.

    This implementation covers the models referenced by the GUI and CLI:
    - Random Forest
    - Gradient Boosting
    - SVM (with probability enabled)
    - Neural Network (MLPClassifier)
    - Logistic Regression

    Attributes:
        models: Dict of trained model objects keyed by display name.
        results: Dict of metrics keyed by display name.
    """

    def __init__(self):
        self.models: Dict[str, object] = {}
        self.results: Dict[str, Dict[str, float]] = {}

    def _build_model(self, name: str):
        """Factory to build a model by display name."""
        if name == 'Random Forest':
            return RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
        if name == 'Gradient Boosting':
            return GradientBoostingClassifier(random_state=42)
        if name == 'SVM':
            # Enable probability for ROC curves
            return SVC(kernel='rbf', C=1.0, gamma='scale', probability=True, random_state=42)
        if name == 'Neural Network':
            return MLPClassifier(hidden_layer_sizes=(64,), activation='relu', solver='adam',
                                 max_iter=200, random_state=42)
        if name == 'Logistic Regression':
            return LogisticRegression(max_iter=500, n_jobs=None, random_state=42)
        raise ValueError(f"Unknown model name: {name}")

    def train_all_models(self, X_train, y_train, selected_models: Optional[List[str]] = None):
        """Train selected models and compute training metrics.

        Args:
            X_train: Preprocessed feature matrix.
            y_train: Target vector (binary 0/1 expected).
            selected_models: Optional list of model display names to train.

        Returns:
            Dict of training metrics per model.
        """
        if selected_models is None:
            selected_models = ['Random Forest', 'Gradient Boosting', 'SVM', 'Neural Network', 'Logistic Regression']

        self.models.clear()
        self.results.clear()

        for name in selected_models:
            model = self._build_model(name)
            model.fit(X_train, y_train)

            # Basic training metrics
            y_pred = model.predict(X_train)
            acc = accuracy_score(y_train, y_pred)
            try:
                prec = precision_score(y_train, y_pred, zero_division=0)
                rec = recall_score(y_train, y_pred, zero_division=0)
                f1 = f1_score(y_train, y_pred, zero_division=0)
            except Exception:
                # Fallback for non-binary targets
                prec = precision_score(y_train, y_pred, average='macro', zero_division=0)
                rec = recall_score(y_train, y_pred, average='macro', zero_division=0)
                f1 = f1_score(y_train, y_pred, average='macro', zero_division=0)

            self.models[name] = model
            self.results[name] = {
                'train_accuracy': float(acc),
                'train_precision': float(prec),
                'train_recall': float(rec),
                'train_f1': float(f1),
            }

        return self.results

    def evaluate_all_models(self, X_test, y_test):
        """Evaluate trained models on test set."""
        evaluation = {}
        for name, model in self.models.items():
            y_pred = model.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            try:
                prec = precision_score(y_test, y_pred, zero_division=0)
                rec = recall_score(y_test, y_pred, zero_division=0)
                f1 = f1_score(y_test, y_pred, zero_division=0)
            except Exception:
                prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
                rec = recall_score(y_test, y_pred, average='macro', zero_division=0)
                f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)

            evaluation[name] = {
                'test_accuracy': float(acc),
                'test_precision': float(prec),
                'test_recall': float(rec),
                'test_f1': float(f1),
            }

        return evaluation

    def save_models(self, output_dir: str):
        """Persist trained models to disk and save the best one as best_model.pkl."""
        os.makedirs(output_dir, exist_ok=True)
        best_name = None
        best_score = -np.inf

        for name, model in self.models.items():
            filename = os.path.join(output_dir, f"{name.replace(' ', '_').lower()}.pkl")
            joblib.dump(model, filename)

            # Use train_f1 to select the best model
            metrics = self.results.get(name, {})
            score = metrics.get('train_f1', metrics.get('train_accuracy', 0.0))
            if score > best_score:
                best_score = score
                best_name = name

        # Save the best model as a convenience for real-time analyzer
        if best_name is not None:
            best_model_path = os.path.join(output_dir, 'best_model.pkl')
            joblib.dump(self.models[best_name], best_model_path)

    def load_models(self, models_dir: str):
        """Load models from a directory into self.models."""
        if not os.path.isdir(models_dir):
            raise FileNotFoundError(f"Models directory not found: {models_dir}")

        loaded = 0
        for fname in os.listdir(models_dir):
            if fname.endswith('.pkl') and fname != 'preprocessor.pkl':
                path = os.path.join(models_dir, fname)
                try:
                    model = joblib.load(path)
                    # Convert filename back to display name
                    name = fname[:-4].replace('_', ' ').title()
                    if name == 'Best Model':
                        # Keep as special entry
                        name = 'Best Model'
                    self.models[name] = model
                    loaded += 1
                except Exception:
                    continue

        if loaded == 0:
            raise FileNotFoundError(f"No models found in {models_dir}")