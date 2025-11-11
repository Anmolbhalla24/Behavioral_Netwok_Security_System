import socket
import struct
import threading
import time
import os
from datetime import datetime
import pandas as pd
import numpy as np
from collections import deque, defaultdict
import joblib
from data_preprocessing import DataPreprocessor

class RealTimePacketAnalyzer:
    def __init__(self, model_path='models/best_model.pkl', preprocessor_path='models/preprocessor.pkl'):
        self.model = None
        self.preprocessor = None
        self.model_path = model_path
        self.preprocessor_path = preprocessor_path
        
        # Real-time analysis parameters
        self.packet_buffer = deque(maxlen=1000)
        self.flow_cache = defaultdict(dict)
        self.anomaly_history = deque(maxlen=1000)
        
        # Statistics
        self.total_packets = 0
        self.anomaly_count = 0
        self.normal_count = 0
        self.start_time = None
        
        # Load model and preprocessor
        self.load_model_and_preprocessor()
        
    def load_model_and_preprocessor(self):
        """Load the trained model and preprocessor"""
        try:
            # Load model
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                print(f"Model loaded from {self.model_path}")
            else:
                print("Warning: Model file not found. Using default behavior.")
            
            # Load preprocessor
            if os.path.exists(self.preprocessor_path):
                self.preprocessor = DataPreprocessor()
                self.preprocessor.load_preprocessor(self.preprocessor_path)
                print(f"Preprocessor loaded from {self.preprocessor_path}")
            else:
                print("Warning: Preprocessor file not found. Using default behavior.")
                
        except Exception as e:
            print(f"Error loading model/preprocessor: {e}")
    
    def extract_packet_features(self, packet_data):
        """Extract features from packet data"""
        try:
            # Parse IP header (assuming IPv4)
            ip_header = packet_data[14:34]  # Skip Ethernet header
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            if version != 4:  # Not IPv4
                return None
            
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            # Extract port information if TCP/UDP
            src_port = 0
            dst_port = 0
            packet_length = len(packet_data)
            
            if protocol in [6, 17]:  # TCP or UDP
                transport_header = packet_data[34:42]
                if len(transport_header) >= 8:
                    ports = struct.unpack('!HH', transport_header[:4])
                    src_port = ports[0]
                    dst_port = ports[1]
            
            # Create feature dictionary
            features = {
                'srcip': src_ip,
                'dstip': dst_ip,
                'sport': src_port,
                'dsport': dst_port,
                'proto': self.get_protocol_name(protocol),
                'state': 'INT',  # Default state
                'dur': 0.0,  # Will be calculated for flows
                'spkts': 1,
                'dpkts': 0,
                'sbytes': packet_length,
                'dbytes': 0,
                'rate': 0.0,
                'sttl': 64,  # Default TTL
                'dttl': 0,
                'sload': 0.0,
                'dload': 0.0,
                'sloss': 0,
                'dloss': 0,
                'sinpkt': 0.0,
                'dinpkt': 0.0,
                'sjit': 0.0,
                'djit': 0.0,
                'swin': 0,
                'stcpb': 0,
                'dtcpb': 0,
                'dwin': 0,
                'tcprtt': 0.0,
                'synack': 0.0,
                'ackdat': 0.0,
                'smean': packet_length,
                'dmean': 0,
                'trans_depth': 0,
                'response_body_len': 0,
                'ct_srv_src': 1,
                'ct_state_ttl': 1,
                'ct_dst_ltm': 1,
                'ct_src_dport_ltm': 1,
                'ct_dst_sport_ltm': 1,
                'ct_dst_src_ltm': 1,
                'is_ftp_login': 0,
                'ct_ftp_cmd': 0,
                'ct_flw_http_mthd': 0,
                'ct_src_ltm': 1,
                'ct_srv_dst': 1,
                'is_sm_ips_ports': 1 if src_ip == dst_ip and src_port == dst_port else 0,
                'service': self.get_service_name(dst_port, protocol),
                'attack_cat': 'Normal',
                'label': 0
            }
            
            return features
            
        except Exception as e:
            print(f"Error extracting packet features: {e}")
            return None
    
    def get_protocol_name(self, protocol_num):
        """Convert protocol number to name"""
        protocol_map = {
            1: 'icmp',
            6: 'tcp',
            17: 'udp',
            2: 'igmp',
            47: 'gre'
        }
        return protocol_map.get(protocol_num, 'other')
    
    def get_service_name(self, port, protocol):
        """Get service name from port"""
        common_services = {
            80: 'http',
            443: 'https',
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            110: 'pop3',
            143: 'imap',
            3389: 'rdp'
        }
        
        if port in common_services:
            return common_services[port]
        elif protocol == 6:  # TCP
            return 'other-tcp'
        elif protocol == 17:  # UDP
            return 'other-udp'
        else:
            return '-'
    
    def analyze_packet(self, packet_data):
        """Analyze a single packet for anomalies"""
        self.total_packets += 1
        
        # Extract features
        features = self.extract_packet_features(packet_data)
        if features is None:
            return {'status': 'error', 'message': 'Failed to extract features'}
        
        # Add to buffer
        self.packet_buffer.append({
            'timestamp': datetime.now(),
            'features': features,
            'raw_packet': packet_data
        })
        
        # Analyze with model if available
        if self.model is not None and self.preprocessor is not None:
            try:
                # Convert to DataFrame
                df = pd.DataFrame([features])
                
                # Preprocess
                X_processed, _ = self.preprocessor.preprocess_test_data(df)
                
                # Make prediction
                prediction = self.model.predict(X_processed)[0]
                probability = self.model.predict_proba(X_processed)[0] if hasattr(self.model, 'predict_proba') else None
                
                # Update statistics
                if prediction == 1:  # Anomaly
                    self.anomaly_count += 1
                    anomaly_result = {
                        'timestamp': datetime.now(),
                        'prediction': 'ANOMALY',
                        'confidence': probability[1] if probability is not None else 1.0,
                        'features': features
                    }
                    self.anomaly_history.append(anomaly_result)
                else:
                    self.normal_count += 1
                
                return {
                    'status': 'success',
                    'prediction': 'ANOMALY' if prediction == 1 else 'NORMAL',
                    'confidence': probability[1] if probability is not None and prediction == 1 else probability[0] if probability is not None else 1.0,
                    'features': features
                }
                
            except Exception as e:
                print(f"Error during prediction: {e}")
                return {'status': 'error', 'message': f'Prediction error: {e}'}
        else:
            # Fallback to simple rule-based detection
            is_anomaly = self.simple_rule_based_detection(features)
            
            if is_anomaly:
                self.anomaly_count += 1
                return {
                    'status': 'success',
                    'prediction': 'ANOMALY',
                    'confidence': 0.8,
                    'method': 'rule-based',
                    'features': features
                }
            else:
                self.normal_count += 1
                return {
                    'status': 'success',
                    'prediction': 'NORMAL',
                    'confidence': 0.9,
                    'method': 'rule-based',
                    'features': features
                }
    
    def simple_rule_based_detection(self, features):
        """Simple rule-based anomaly detection"""
        # Check for suspicious patterns
        
        # Very large packet size
        if features['sbytes'] > 1500:
            return True
        
        # Suspicious ports
        suspicious_ports = [135, 139, 445, 1433, 3389]
        if features['dsport'] in suspicious_ports or features['sport'] in suspicious_ports:
            return True
        
        # ICMP flood detection
        if features['proto'] == 'icmp' and self.get_recent_icmp_count() > 100:
            return True
        
        # Port scan detection
        dst_ip = features['dstip']
        current_time = datetime.now()
        if dst_ip in self.flow_cache:
            flows = self.flow_cache[dst_ip]
            unique_ports = len(set(flow['dsport'] for flow in flows if 
                                   (current_time - flow['timestamp']).seconds < 60))
            if unique_ports > 10:
                return True
        
        return False
    
    def get_recent_icmp_count(self, time_window=60):
        """Get count of recent ICMP packets"""
        current_time = datetime.now()
        icmp_count = 0
        
        for packet_info in self.packet_buffer:
            if ((current_time - packet_info['timestamp']).seconds < time_window and
                packet_info['features']['proto'] == 'icmp'):
                icmp_count += 1
        
        return icmp_count
    
    def get_statistics(self):
        """Get current statistics"""
        if self.start_time is None:
            uptime = 0
        else:
            uptime = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'total_packets': self.total_packets,
            'anomaly_count': self.anomaly_count,
            'normal_count': self.normal_count,
            'anomaly_rate': self.anomaly_count / max(self.total_packets, 1) * 100,
            'uptime_seconds': uptime,
            'recent_anomalies': list(self.anomaly_history)[-10:]
        }
    
    def start_real_time_analysis(self, interface='Ethernet', duration=None):
        """Start real-time packet analysis"""
        print(f"Starting real-time packet analysis on interface: {interface}")
        self.start_time = datetime.now()
        
        try:
            # Create raw socket (requires administrator privileges)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((interface, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            print("Real-time analysis started. Press Ctrl+C to stop.")
            
            start_time = time.time()
            while True:
                if duration and (time.time() - start_time) > duration:
                    break
                
                try:
                    # Receive packet
                    packet_data, addr = sock.recvfrom(65535)
                    
                    # Analyze packet
                    result = self.analyze_packet(packet_data)
                    
                    # Print results for anomalies
                    if result['status'] == 'success' and result['prediction'] == 'ANOMALY':
                        print(f"🚨 ANOMALY DETECTED - Confidence: {result['confidence']:.2f}")
                        print(f"   Source: {result['features']['srcip']}:{result['features']['sport']}")
                        print(f"   Destination: {result['features']['dstip']}:{result['features']['dsport']}")
                        print(f"   Protocol: {result['features']['proto']}")
                        print()
                    
                except KeyboardInterrupt:
                    print("\nStopping real-time analysis...")
                    break
                except Exception as e:
                    print(f"Error processing packet: {e}")
                    continue
            
            # Turn off promiscuous mode
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            
        except Exception as e:
            print(f"Error starting real-time analysis: {e}")
            print("Make sure you're running with administrator privileges.")
    
    def analyze_pcap_file(self, pcap_file):
        """Analyze packets from a PCAP file"""
        print(f"Analyzing PCAP file: {pcap_file}")
        
        try:
            # This is a simplified PCAP reader
            # In a real implementation, you might use scapy or dpkt
            with open(pcap_file, 'rb') as f:
                # Skip PCAP global header
                f.read(24)
                
                packet_count = 0
                while True:
                    # Read packet header
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break
                    
                    # Parse packet header
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', packet_header)
                    
                    # Read packet data
                    packet_data = f.read(incl_len)
                    
                    # Analyze packet
                    result = self.analyze_packet(packet_data)
                    
                    packet_count += 1
                    if packet_count % 1000 == 0:
                        print(f"Analyzed {packet_count} packets...")
                    
                    # Print anomalies
                    if result['status'] == 'success' and result['prediction'] == 'ANOMALY':
                        print(f"🚨 ANOMALY in packet {packet_count}")
        
        except Exception as e:
            print(f"Error analyzing PCAP file: {e}")

def main():
    """Example usage"""
    analyzer = RealTimePacketAnalyzer()
    
    # Example: Analyze a sample packet
    sample_packet = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00' + \
                   b'\x45\x00\x00\x3c\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01' + \
                   b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00' + \
                   b'\x50\x02\x20\x00\x00\x00\x00\x00'
    
    result = analyzer.analyze_packet(sample_packet)
    print(f"Analysis result: {result}")
    
    # Print statistics
    stats = analyzer.get_statistics()
    print(f"Statistics: {stats}")

if __name__ == "__main__":
    main()