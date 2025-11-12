import os
from typing import Dict, Optional

import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay, roc_curve, auc


class NetworkSecurityVisualizer:
    """Visualization helpers used by the GUI and CLI flows."""

    def plot_confusion_matrix(self, y_true, y_pred, model_name: str, ax):
        disp = ConfusionMatrixDisplay.from_predictions(y_true, y_pred, ax=ax, colorbar=False)
        ax.set_title(f"Confusion Matrix - {model_name}")

    def plot_roc_curve(self, y_true, y_pred_proba, model_name: str, ax):
        fpr, tpr, _ = roc_curve(y_true, y_pred_proba)
        roc_auc = auc(fpr, tpr)
        ax.plot(fpr, tpr, label=f"{model_name} (AUC={roc_auc:.2f})")
        ax.plot([0, 1], [0, 1], 'k--', linewidth=0.8)
        ax.set_xlabel('False Positive Rate')
        ax.set_ylabel('True Positive Rate')
        ax.set_title('ROC Curves')

    def plot_feature_importance(self, feature_importances, feature_names: Optional[list], ax):
        if feature_names is None:
            ax.bar(range(len(feature_importances)), feature_importances)
            ax.set_xticks([])
        else:
            # Show top-k features for readability
            k = min(20, len(feature_importances))
            importances = feature_importances
            idx = sorted(range(len(importances)), key=lambda i: importances[i], reverse=True)[:k]
            names = [feature_names[i] for i in idx]
            vals = [importances[i] for i in idx]
            ax.barh(names, vals)
            ax.invert_yaxis()
        ax.set_title('Feature Importance (Random Forest)')

    def plot_attack_distribution(self, y_series, ax):
        counts = y_series.value_counts()
        counts.plot(kind='bar', ax=ax)
        ax.set_title('Attack Distribution (label counts)')
        ax.set_xlabel('Label')
        ax.set_ylabel('Count')

    def plot_model_comparison(self, results: Dict[str, Dict[str, float]], ax):
        names = list(results.keys())
        scores = [results[n].get('train_accuracy', 0.0) for n in names]
        ax.bar(names, scores)
        ax.set_title('Model Training Accuracy Comparison')
        ax.set_ylabel('Accuracy')
        ax.set_xticklabels(names, rotation=45, ha='right')

    def generate_visual_report(self, models_manager, X_test, y_test, output_dir: str):
        """Generate and save a composite visual report for all models."""
        os.makedirs(output_dir, exist_ok=True)

        # Confusion matrices
        fig_cm, axes = plt.subplots(2, 3, figsize=(15, 10))
        axes = axes.flatten()
        for i, (name, model) in enumerate(models_manager.models.items()):
            if i >= len(axes):
                break
            y_pred = model.predict(X_test)
            self.plot_confusion_matrix(y_test, y_pred, name, axes[i])
        fig_cm.tight_layout()
        fig_cm.savefig(os.path.join(output_dir, 'confusion_matrices.png'))
        plt.close(fig_cm)

        # ROC curves
        fig_roc, ax_roc = plt.subplots(figsize=(10, 8))
        for name, model in models_manager.models.items():
            if hasattr(model, 'predict_proba'):
                y_prob = model.predict_proba(X_test)[:, 1]
            else:
                # Fallback if decision_function exists
                if hasattr(model, 'decision_function'):
                    # Map decision function to [0,1] via min-max for plotting only
                    raw = model.decision_function(X_test)
                    mn, mx = raw.min(), raw.max()
                    y_prob = (raw - mn) / (mx - mn + 1e-12)
                else:
                    continue
            self.plot_roc_curve(y_test, y_prob, name, ax_roc)
        ax_roc.legend()
        fig_roc.tight_layout()
        fig_roc.savefig(os.path.join(output_dir, 'roc_curves.png'))
        plt.close(fig_roc)

        # Feature importance (Random Forest)
        if 'Random Forest' in models_manager.models:
            rf = models_manager.models['Random Forest']
            if hasattr(rf, 'feature_importances_'):
                fig_fi, ax_fi = plt.subplots(figsize=(12, 8))
                # The models manager does not track feature names; the caller should
                # provide them via the DataPreprocessor when needed in the GUI.
                self.plot_feature_importance(rf.feature_importances_, None, ax_fi)
                fig_fi.tight_layout()
                fig_fi.savefig(os.path.join(output_dir, 'feature_importance_random_forest.png'))
                plt.close(fig_fi)