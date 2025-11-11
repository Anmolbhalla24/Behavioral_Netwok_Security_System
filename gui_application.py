import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
from datetime import datetime
import threading
import time
import pandas as pd
import numpy as np
from collections import deque
import os

from data_preprocessing import DataPreprocessor
from network_security_models import NetworkSecurityModels
from visualization import NetworkSecurityVisualizer
from real_time_analyzer import RealTimePacketAnalyzer

class NetworkSecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security System")
        self.root.geometry("1200x800")
        
        # Initialize components
        self.preprocessor = None
        self.models = None
        self.visualizer = NetworkSecurityVisualizer()
        self.real_time_analyzer = None
        
        # Data storage for real-time analysis
        self.packet_buffer = deque(maxlen=1000)
        self.anomaly_history = deque(maxlen=100)
        self.is_analyzing = False
        
        # Create GUI
        self.create_widgets()
        
        # Start update loop
        self.update_gui()
    
    def create_widgets(self):
        """Create the main GUI widgets"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_data_tab()
        self.create_models_tab()
        self.create_real_time_tab()
        self.create_visualization_tab()
        self.create_logs_tab()
    
    def create_data_tab(self):
        """Create data preprocessing tab"""
        data_frame = ttk.Frame(self.notebook)
        self.notebook.add(data_frame, text="Data Preprocessing")
        
        # Data loading section
        load_frame = ttk.LabelFrame(data_frame, text="Load Data", padding=10)
        load_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(load_frame, text="Training Data:").grid(row=0, column=0, sticky='w')
        self.train_path = tk.StringVar(value="UNSW_NB15_training-set.csv")
        ttk.Entry(load_frame, textvariable=self.train_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(load_frame, text="Browse", command=self.browse_train_file).grid(row=0, column=2)
        
        ttk.Label(load_frame, text="Testing Data:").grid(row=1, column=0, sticky='w')
        self.test_path = tk.StringVar(value="UNSW_NB15_testing-set.csv")
        ttk.Entry(load_frame, textvariable=self.test_path, width=50).grid(row=1, column=1, padx=5)
        ttk.Button(load_frame, text="Browse", command=self.browse_test_file).grid(row=1, column=2)
        
        ttk.Button(load_frame, text="Load & Preprocess Data", 
                  command=self.load_and_preprocess_data).grid(row=2, column=1, pady=10)
        
        # Data info section
        info_frame = ttk.LabelFrame(data_frame, text="Data Information", padding=10)
        info_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.data_info_text = scrolledtext.ScrolledText(info_frame, height=15, width=80)
        self.data_info_text.pack(fill='both', expand=True)
        
        # Progress bar
        self.data_progress = ttk.Progressbar(data_frame, mode='indeterminate')
        self.data_progress.pack(fill='x', padx=10, pady=5)
    
    def create_models_tab(self):
        """Create models training tab"""
        models_frame = ttk.Frame(self.notebook)
        self.notebook.add(models_frame, text="ML Models")
        
        # Model selection
        model_frame = ttk.LabelFrame(models_frame, text="Model Training", padding=10)
        model_frame.pack(fill='x', padx=10, pady=5)
        
        self.selected_models = {}
        model_types = ['Random Forest', 'Gradient Boosting', 'SVM', 'Neural Network', 'Logistic Regression']
        
        for i, model_type in enumerate(model_types):
            self.selected_models[model_type] = tk.BooleanVar(value=True)
            ttk.Checkbutton(model_frame, text=model_type, 
                           variable=self.selected_models[model_type]).grid(row=i//3, column=i%3, sticky='w', padx=5)
        
        ttk.Button(model_frame, text="Train Selected Models", 
                  command=self.train_models).grid(row=len(model_types)//3 + 1, column=1, pady=10)
        
        # Model results
        results_frame = ttk.LabelFrame(models_frame, text="Model Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.model_results_text = scrolledtext.ScrolledText(results_frame, height=15, width=80)
        self.model_results_text.pack(fill='both', expand=True)
        
        # Progress bar
        self.model_progress = ttk.Progressbar(models_frame, mode='indeterminate')
        self.model_progress.pack(fill='x', padx=10, pady=5)
    
    def create_real_time_tab(self):
        """Create real-time analysis tab"""
        real_time_frame = ttk.Frame(self.notebook)
        self.notebook.add(real_time_frame, text="Real-Time Analysis")
        
        # Control section
        control_frame = ttk.LabelFrame(real_time_frame, text="Real-Time Controls", padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(control_frame, text="Start Real-Time Analysis", 
                  command=self.start_real_time_analysis).grid(row=0, column=0, padx=5)
        ttk.Button(control_frame, text="Stop Analysis", 
                  command=self.stop_real_time_analysis).grid(row=0, column=1, padx=5)
        ttk.Button(control_frame, text="Load Model", 
                  command=self.load_model_for_real_time).grid(row=0, column=2, padx=5)
        
        # Statistics section
        stats_frame = ttk.LabelFrame(real_time_frame, text="Real-Time Statistics", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        self.stats_labels = {}
        stats = ['Total Packets', 'Anomalies', 'Normal', 'Anomaly Rate (%)', 'Uptime (s)']
        
        for i, stat in enumerate(stats):
            ttk.Label(stats_frame, text=f"{stat}:").grid(row=i, column=0, sticky='w', padx=5)
            self.stats_labels[stat] = ttk.Label(stats_frame, text="0")
            self.stats_labels[stat].grid(row=i, column=1, sticky='w', padx=5)
        
        # Recent anomalies
        anomalies_frame = ttk.LabelFrame(real_time_frame, text="Recent Anomalies", padding=10)
        anomalies_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.anomalies_text = scrolledtext.ScrolledText(anomalies_frame, height=10, width=80)
        self.anomalies_text.pack(fill='both', expand=True)
        
        # Real-time chart
        chart_frame = ttk.LabelFrame(real_time_frame, text="Anomaly Detection Chart", padding=10)
        chart_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.create_real_time_chart(chart_frame)
    
    def create_real_time_chart(self, parent):
        """Create real-time anomaly detection chart"""
        self.fig, self.ax = plt.subplots(figsize=(10, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, parent)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Initialize data
        self.time_data = deque(maxlen=50)
        self.anomaly_rate_data = deque(maxlen=50)
        self.packet_count_data = deque(maxlen=50)
        
        # Set up the plot
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Rate')
        self.ax.set_title('Real-Time Network Traffic Analysis')
        self.ax.grid(True)
        
        self.line1, = self.ax.plot([], [], 'r-', label='Anomaly Rate (%)', linewidth=2)
        self.line2, = self.ax.plot([], [], 'b-', label='Packet Count', linewidth=2)
        self.ax.legend()
        
        # Start animation
        self.animation = animation.FuncAnimation(self.fig, self.update_chart, 
                                               interval=1000, blit=True)
    
    def create_visualization_tab(self):
        """Create visualization tab"""
        viz_frame = ttk.Frame(self.notebook)
        self.notebook.add(viz_frame, text="Visualizations")
        
        # Visualization controls
        control_frame = ttk.LabelFrame(viz_frame, text="Visualization Options", padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(control_frame, text="Confusion Matrix", 
                  command=self.show_confusion_matrix).grid(row=0, column=0, padx=5)
        ttk.Button(control_frame, text="ROC Curves", 
                  command=self.show_roc_curves).grid(row=0, column=1, padx=5)
        ttk.Button(control_frame, text="Feature Importance", 
                  command=self.show_feature_importance).grid(row=0, column=2, padx=5)
        ttk.Button(control_frame, text="Attack Distribution", 
                  command=self.show_attack_distribution).grid(row=0, column=3, padx=5)
        
        # Visualization canvas
        self.viz_canvas_frame = ttk.LabelFrame(viz_frame, text="Visualization", padding=10)
        self.viz_canvas_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Placeholder for matplotlib canvas
        self.viz_canvas = None
    
    def create_logs_tab(self):
        """Create logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")
        
        # Log controls
        control_frame = ttk.LabelFrame(logs_frame, text="Log Controls", padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(control_frame, text="Clear Logs", 
                  command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Export Logs", 
                  command=self.export_logs).pack(side='left', padx=5)
        
        # Log display
        log_frame = ttk.LabelFrame(logs_frame, text="System Logs", padding=10)
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, width=80)
        self.log_text.pack(fill='both', expand=True)
        
        # Initialize log
        self.log_message("Network Security System initialized.")
    
    def browse_train_file(self):
        """Browse for training file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filename:
            self.train_path.set(filename)
    
    def browse_test_file(self):
        """Browse for testing file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filename:
            self.test_path.set(filename)
    
    def load_and_preprocess_data(self):
        """Load and preprocess data"""
        def load_data():
            try:
                self.data_progress.start()
                self.log_message("Loading and preprocessing data...")
                
                # Initialize preprocessor
                self.preprocessor = DataPreprocessor()
                
                # Load data
                train_data = self.preprocessor.load_data(self.train_path.get())
                test_data = self.preprocessor.load_data(self.test_path.get())
                
                # Preprocess data
                X_train, y_train = self.preprocessor.preprocess_train_data(train_data)
                X_test, y_test = self.preprocessor.preprocess_test_data(test_data)
                
                # Display information
                info = f"""
Data Loading and Preprocessing Complete!

Training Data:
- Shape: {train_data.shape}
- Features: {X_train.shape[1]}
- Samples: {X_train.shape[0]}

Testing Data:
- Shape: {test_data.shape}
- Features: {X_test.shape[1]}
- Samples: {X_test.shape[0]}

Feature Engineering Applied:
- Total bytes, packets per second, byte ratios
- State and service rarity scores
- Variance-based feature selection
- Standard scaling

Data preprocessing pipeline saved to 'models/preprocessor.pkl'
                """
                
                self.data_info_text.delete(1.0, tk.END)
                self.data_info_text.insert(1.0, info)
                
                self.log_message("Data preprocessing completed successfully.")
                
            except Exception as e:
                self.log_message(f"Error loading data: {e}")
                messagebox.showerror("Error", f"Failed to load data: {e}")
            finally:
                self.data_progress.stop()
        
        threading.Thread(target=load_data, daemon=True).start()
    
    def train_models(self):
        """Train machine learning models"""
        def train():
            try:
                if not self.preprocessor:
                    messagebox.showerror("Error", "Please load and preprocess data first.")
                    return
                
                self.model_progress.start()
                self.log_message("Training machine learning models...")
                
                # Initialize models
                self.models = NetworkSecurityModels()
                
                # Get selected models
                selected = [model for model, var in self.selected_models.items() if var.get()]
                
                if not selected:
                    messagebox.showwarning("Warning", "Please select at least one model.")
                    return
                
                # Train models
                results = self.models.train_all_models(X_train, y_train, selected)
                
                # Display results
                results_text = "Model Training Results:\n\n"
                for model_name, metrics in results.items():
                    results_text += f"{model_name}:\n"
                    for metric, value in metrics.items():
                        results_text += f"  {metric}: {value:.4f}\n"
                    results_text += "\n"
                
                self.model_results_text.delete(1.0, tk.END)
                self.model_results_text.insert(1.0, results_text)
                
                self.log_message("Model training completed successfully.")
                
            except Exception as e:
                self.log_message(f"Error training models: {e}")
                messagebox.showerror("Error", f"Failed to train models: {e}")
            finally:
                self.model_progress.stop()
        
        threading.Thread(target=train, daemon=True).start()
    
    def start_real_time_analysis(self):
        """Start real-time packet analysis"""
        try:
            if not self.real_time_analyzer:
                self.real_time_analyzer = RealTimePacketAnalyzer()
            
            self.is_analyzing = True
            self.log_message("Starting real-time packet analysis...")
            
            # Start analysis in separate thread
            threading.Thread(target=self.real_time_analysis_loop, daemon=True).start()
            
        except Exception as e:
            self.log_message(f"Error starting real-time analysis: {e}")
            messagebox.showerror("Error", f"Failed to start real-time analysis: {e}")
    
    def stop_real_time_analysis(self):
        """Stop real-time analysis"""
        self.is_analyzing = False
        self.log_message("Stopping real-time packet analysis...")
    
    def real_time_analysis_loop(self):
        """Real-time analysis loop"""
        while self.is_analyzing:
            try:
                # Simulate packet analysis (in real implementation, this would capture actual packets)
                import random
                
                # Simulate packet data
                packet_data = self.simulate_packet()
                result = self.real_time_analyzer.analyze_packet(packet_data)
                
                if result['status'] == 'success':
                    self.packet_buffer.append({
                        'timestamp': datetime.now(),
                        'result': result
                    })
                    
                    if result['prediction'] == 'ANOMALY':
                        self.anomaly_history.append({
                            'timestamp': datetime.now(),
                            'result': result
                        })
                
                time.sleep(0.1)  # Simulate packet arrival rate
                
            except Exception as e:
                self.log_message(f"Error in real-time analysis: {e}")
                break
    
    def simulate_packet(self):
        """Simulate network packet for demonstration"""
        # Create a simple simulated packet
        import random
        
        # Random source and destination IPs
        src_ip = f"192.168.1.{random.randint(1, 255)}"
        dst_ip = f"10.0.0.{random.randint(1, 255)}"
        
        # Random ports
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21, 25, 53, 135, 139, 445])
        
        # Create packet data (simplified)
        packet = b'\x00' * 14 + b'\x45\x00\x00\x28' + b'\x00' * 20
        
        return packet
    
    def load_model_for_real_time(self):
        """Load trained model for real-time analysis"""
        try:
            if not self.models:
                messagebox.showerror("Error", "Please train models first.")
                return
            
            # Use the best model for real-time analysis
            self.real_time_analyzer.model = self.models.models.get('Random Forest')
            self.real_time_analyzer.preprocessor = self.preprocessor
            
            self.log_message("Model loaded for real-time analysis.")
            messagebox.showinfo("Success", "Model loaded successfully for real-time analysis.")
            
        except Exception as e:
            self.log_message(f"Error loading model: {e}")
            messagebox.showerror("Error", f"Failed to load model: {e}")
    
    def update_chart(self, frame):
        """Update real-time chart"""
        current_time = datetime.now()
        
        # Get statistics
        if self.real_time_analyzer:
            stats = self.real_time_analyzer.get_statistics()
            
            # Update data
            self.time_data.append(current_time)
            self.anomaly_rate_data.append(stats['anomaly_rate'])
            self.packet_count_data.append(stats['total_packets'])
            
            # Update lines
            self.line1.set_data(range(len(self.anomaly_rate_data)), list(self.anomaly_rate_data))
            self.line2.set_data(range(len(self.packet_count_data)), list(self.packet_count_data))
            
            # Update axis
            self.ax.relim()
            self.ax.autoscale_view()
            
            # Update statistics display
            self.update_statistics_display(stats)
        
        return self.line1, self.line2
    
    def update_statistics_display(self, stats):
        """Update statistics display"""
        self.stats_labels['Total Packets'].config(text=str(stats['total_packets']))
        self.stats_labels['Anomalies'].config(text=str(stats['anomaly_count']))
        self.stats_labels['Normal'].config(text=str(stats['normal_count']))
        self.stats_labels['Anomaly Rate (%)'].config(text=f"{stats['anomaly_rate']:.2f}")
        self.stats_labels['Uptime (s)'].config(text=f"{stats['uptime_seconds']:.1f}")
        
        # Update recent anomalies
        if stats['recent_anomalies']:
            self.anomalies_text.delete(1.0, tk.END)
            for anomaly in stats['recent_anomalies']:
                self.anomalies_text.insert(tk.END, 
                    f"[{anomaly['timestamp'].strftime('%H:%M:%S')}] "
                    f"ANOMALY - Confidence: {anomaly['confidence']:.2f}\n")
    
    def show_confusion_matrix(self):
        """Show confusion matrix visualization"""
        try:
            if not self.models:
                messagebox.showerror("Error", "Please train models first.")
                return
            
            # Clear previous visualization
            if self.viz_canvas:
                self.viz_canvas.get_tk_widget().destroy()
            
            # Create new figure
            fig, axes = plt.subplots(2, 3, figsize=(15, 10))
            axes = axes.flatten()
            
            # Plot confusion matrices for each model
            for i, (model_name, model) in enumerate(self.models.models.items()):
                if i < len(axes):
                    # Get predictions
                    y_pred = model.predict(X_test)
                    
                    # Plot confusion matrix
                    self.visualizer.plot_confusion_matrix(y_test, y_pred, 
                                                        model_name, axes[i])
            
            # Create canvas
            self.viz_canvas = FigureCanvasTkAgg(fig, self.viz_canvas_frame)
            self.viz_canvas.get_tk_widget().pack(fill='both', expand=True)
            self.viz_canvas.draw()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show confusion matrices: {e}")
    
    def show_roc_curves(self):
        """Show ROC curves"""
        try:
            if not self.models:
                messagebox.showerror("Error", "Please train models first.")
                return
            
            # Clear previous visualization
            if self.viz_canvas:
                self.viz_canvas.get_tk_widget().destroy()
            
            # Create new figure
            fig, ax = plt.subplots(figsize=(10, 8))
            
            # Plot ROC curves for each model
            for model_name, model in self.models.models.items():
                # Get predictions
                if hasattr(model, 'predict_proba'):
                    y_pred_proba = model.predict_proba(X_test)[:, 1]
                else:
                    y_pred_proba = model.decision_function(X_test)
                
                self.visualizer.plot_roc_curve(y_test, y_pred_proba, model_name, ax)
            
            ax.legend()
            
            # Create canvas
            self.viz_canvas = FigureCanvasTkAgg(fig, self.viz_canvas_frame)
            self.viz_canvas.get_tk_widget().pack(fill='both', expand=True)
            self.viz_canvas.draw()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show ROC curves: {e}")
    
    def show_feature_importance(self):
        """Show feature importance"""
        try:
            if not self.models:
                messagebox.showerror("Error", "Please train models first.")
                return
            
            # Clear previous visualization
            if self.viz_canvas:
                self.viz_canvas.get_tk_widget().destroy()
            
            # Create new figure
            fig, ax = plt.subplots(figsize=(12, 8))
            
            # Get feature importance from Random Forest
            if 'Random Forest' in self.models.models:
                rf_model = self.models.models['Random Forest']
                if hasattr(rf_model, 'feature_importances_'):
                    self.visualizer.plot_feature_importance(
                        rf_model.feature_importances_, 
                        self.preprocessor.selected_features if self.preprocessor else None,
                        ax
                    )
            
            # Create canvas
            self.viz_canvas = FigureCanvasTkAgg(fig, self.viz_canvas_frame)
            self.viz_canvas.get_tk_widget().pack(fill='both', expand=True)
            self.viz_canvas.draw()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show feature importance: {e}")
    
    def show_attack_distribution(self):
        """Show attack distribution"""
        try:
            # Clear previous visualization
            if self.viz_canvas:
                self.viz_canvas.get_tk_widget().destroy()
            
            # Create new figure
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # Plot attack distribution
            if hasattr(self, 'y_train'):
                self.visualizer.plot_attack_distribution(self.y_train, ax1)
            
            # Plot model comparison
            if self.models and hasattr(self.models, 'results'):
                self.visualizer.plot_model_comparison(self.models.results, ax2)
            
            # Create canvas
            self.viz_canvas = FigureCanvasTkAgg(fig, self.viz_canvas_frame)
            self.viz_canvas.get_tk_widget().pack(fill='both', expand=True)
            self.viz_canvas.draw()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show attack distribution: {e}")
    
    def clear_logs(self):
        """Clear log display"""
        self.log_text.delete(1.0, tk.END)
    
    def export_logs(self):
        """Export logs to file"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                  filetypes=[("Text files", "*.txt")])
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {e}")
    
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
    
    def update_gui(self):
        """Update GUI periodically"""
        try:
            # Update any real-time components here
            pass
        except Exception as e:
            pass
        
        # Schedule next update
        self.root.after(1000, self.update_gui)

def main():
    """Main function"""
    root = tk.Tk()
    app = NetworkSecurityGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()