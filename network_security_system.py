import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ------------------- Global Variables -------------------
captured_packets = []
packet_features = pd.DataFrame()
model = None

# ------------------- Packet Capture -------------------
def packet_callback(packet):
    try:
        pkt_info = {
            "src_ip": packet[IP].src if IP in packet else "0.0.0.0",
            "dst_ip": packet[IP].dst if IP in packet else "0.0.0.0",
            "protocol": packet[IP].proto if IP in packet else 0,
            "length": len(packet)
        }
        captured_packets.append(pkt_info)
    except Exception as e:
        print("Packet error:", e)

def start_capture(interface="Ethernet"):
    sniff(prn=packet_callback, store=False, iface=interface)

# ------------------- Feature Extraction -------------------
def extract_features():
    global captured_packets, packet_features
    if not captured_packets:
        return pd.DataFrame()
    packet_features = pd.DataFrame(captured_packets)
    # Convert categorical protocol to numeric
    packet_features['protocol'] = packet_features['protocol'].apply(lambda x: int(x))
    return packet_features

# ------------------- Anomaly Detection -------------------
def train_model():
    global model, packet_features
    if packet_features.empty:
        messagebox.showwarning("Warning", "No packets captured yet!")
        return
    X = packet_features[['protocol', 'length']].values
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)
    messagebox.showinfo("Info", "Isolation Forest model trained on captured data!")

def detect_anomalies():
    global model, packet_features
    if model is None:
        messagebox.showwarning("Warning", "Train the model first!")
        return
    X = packet_features[['protocol', 'length']].values
    preds = model.predict(X)
    packet_features['anomaly'] = preds
    anomalies = packet_features[packet_features['anomaly'] == -1]
    messagebox.showinfo("Anomalies Detected", f"Number of anomalies: {len(anomalies)}")
    plot_anomalies(anomalies)

# ------------------- Visualization -------------------
def plot_anomalies(anomalies):
    fig, ax = plt.subplots(figsize=(6,4))
    ax.scatter(packet_features['length'], packet_features['protocol'], c='blue', label='Normal')
    if not anomalies.empty:
        ax.scatter(anomalies['length'], anomalies['protocol'], c='red', label='Anomaly')
    ax.set_xlabel("Packet Length")
    ax.set_ylabel("Protocol Number")
    ax.set_title("Network Traffic Anomalies")
    ax.legend()

    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=10)

# ------------------- GUI -------------------
def start_capture_thread():
    t = threading.Thread(target=start_capture, daemon=True)
    t.start()
    messagebox.showinfo("Info", "Packet capture started...")

root = tk.Tk()
root.title("Intelligent Network Security and Diagnostics System")
root.geometry("700x600")

tk.Label(root, text="Intelligent Network Security & Diagnostics System", font=("Arial", 16, "bold")).pack(pady=10)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

ttk.Button(btn_frame, text="Start Packet Capture", command=start_capture_thread).grid(row=0, column=0, padx=10)
ttk.Button(btn_frame, text="Extract Features", command=extract_features).grid(row=0, column=1, padx=10)
ttk.Button(btn_frame, text="Train Isolation Forest", command=train_model).grid(row=0, column=2, padx=10)
ttk.Button(btn_frame, text="Detect Anomalies", command=detect_anomalies).grid(row=0, column=3, padx=10)

root.mainloop()
