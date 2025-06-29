import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import threading
from collections import defaultdict, deque
import datetime
import os
import json
import time
import sqlite3
import hashlib
import ipaddress
from threading import Lock
import webbrowser

# Global state and counters
sniffing = False
sniff_thread = None
captured_packets = []  # Stores captured packet objects for detailed view and saving
packet_display_index = 0  # Unique ID for each packet in Treeview
protocol_counter = defaultdict(int)
total_bytes_sniffed = 0
packet_lock = Lock()  # Thread safety for packet operations
suspicious_ips = set()  # Track suspicious IP addresses
connection_tracker = defaultdict(int)  # Track connections per IP
bandwidth_tracker = deque(maxlen=60)  # Track bandwidth over time (60 seconds)

class DatabaseManager:
    """Manages SQLite database for packet storage and analysis."""
    def __init__(self, db_path="packet_analysis.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                length INTEGER,
                info TEXT,
                packet_hash TEXT UNIQUE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip_address TEXT,
                activity_type TEXT,
                description TEXT,
                severity INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_packet(self, packet_info):
        """Store packet information in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create a hash for duplicate detection
            packet_hash = hashlib.md5(
                f"{packet_info['timestamp']}{packet_info['src_ip']}{packet_info['dst_ip']}{packet_info['protocol']}".encode()
            ).hexdigest()
            
            cursor.execute('''
                INSERT OR IGNORE INTO packets 
                (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length, info, packet_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info['timestamp'], packet_info['src_ip'], packet_info['dst_ip'],
                packet_info['protocol'], packet_info.get('src_port', 0), 
                packet_info.get('dst_port', 0), packet_info['length'], 
                packet_info['info'], packet_hash
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database error: {e}")
    
    def log_suspicious_activity(self, ip_address, activity_type, description, severity=1):
        """Log suspicious network activity."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO suspicious_activity 
                (timestamp, ip_address, activity_type, description, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.datetime.now().isoformat(), ip_address, activity_type, description, severity))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database error: {e}")

class SecurityAnalyzer:
    """Analyzes network traffic for security threats."""
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.port_scan_threshold = 10  # Number of ports to trigger port scan alert
        self.connection_threshold = 50  # Number of connections to trigger alert
        self.known_malicious_ports = {1337, 31337, 6667, 6668, 6669}  # Example malicious ports
        self.suspicious_patterns = [
            b'select * from',
            b'union select',
            b'<script>',
            b'javascript:',
            b'../../etc/passwd'
        ]
    
    def analyze_packet(self, packet, summary_info):
        """Analyze packet for security threats."""
        src_ip = summary_info.get('src_ip', '')
        dst_ip = summary_info.get('dst_ip', '')
        
        if src_ip and src_ip != '-':
            # Track connections per IP
            connection_tracker[src_ip] += 1
            
            # Check for port scanning
            if connection_tracker[src_ip] > self.port_scan_threshold:
                self.detect_port_scan(src_ip)
            
            # Check for connection flooding
            if connection_tracker[src_ip] > self.connection_threshold:
                self.detect_connection_flood(src_ip)
            
            # Check for malicious ports
            if summary_info.get('dst_port') in self.known_malicious_ports:
                self.detect_malicious_port(src_ip, summary_info.get('dst_port'))
        
        # Check for suspicious payload patterns
        if Raw in packet:
            self.analyze_payload(packet[Raw].load, src_ip)
    
    def detect_port_scan(self, ip_address):
        """Detect potential port scanning."""
        if ip_address not in suspicious_ips:
            suspicious_ips.add(ip_address)
            self.db_manager.log_suspicious_activity(
                ip_address, "Port Scan", 
                f"Potential port scan detected from {ip_address}", 
                severity=2
            )
    
    def detect_connection_flood(self, ip_address):
        """Detect connection flooding."""
        if ip_address not in suspicious_ips:
            suspicious_ips.add(ip_address)
            self.db_manager.log_suspicious_activity(
                ip_address, "Connection Flood", 
                f"Connection flooding detected from {ip_address}", 
                severity=3
            )
    
    def detect_malicious_port(self, ip_address, port):
        """Detect connection to known malicious ports."""
        self.db_manager.log_suspicious_activity(
            ip_address, "Malicious Port", 
            f"Connection to suspicious port {port} from {ip_address}", 
            severity=2
        )
    
    def analyze_payload(self, payload, src_ip):
        """Analyze packet payload for suspicious patterns."""
        payload_lower = payload.lower()
        for pattern in self.suspicious_patterns:
            if pattern in payload_lower:
                self.db_manager.log_suspicious_activity(
                    src_ip, "Suspicious Payload", 
                    f"Suspicious pattern detected in payload from {src_ip}", 
                    severity=2
                )
                break

class SnifferEngine:
    """Handles the actual Scapy sniffing logic."""
    def __init__(self, callback):
        self.callback = callback
        self.stop_sniff_event = threading.Event()
        self.packet_count = 0
        self.start_time = None

    def start_sniff(self, iface, bpf_filter, packet_limit=0):
        """Starts sniffing on a separate thread."""
        self.stop_sniff_event.clear()
        self.start_time = time.time()
        self.packet_count = 0
        
        try:
            # Enhanced sniffing with packet limit option
            def stop_condition(packet):
                self.packet_count += 1
                if packet_limit > 0 and self.packet_count >= packet_limit:
                    return True
                return self.stop_sniff_event.is_set()
            
            sniff(iface=iface, prn=self.callback, filter=bpf_filter, 
                  store=0, stop_filter=stop_condition)
        except PermissionError:
            self.callback(None, error="Permission denied. Please run as root/administrator.")
        except Exception as e:
            self.callback(None, error=f"An error occurred during sniffing: {e}")

    def stop_sniff(self):
        """Signals the sniff thread to stop."""
        self.stop_sniff_event.set()

    def get_capture_stats(self):
        """Get capture statistics."""
        if self.start_time:
            duration = time.time() - self.start_time
            pps = self.packet_count / duration if duration > 0 else 0
            return {
                'packets': self.packet_count,
                'duration': duration,
                'pps': pps
            }
        return None

class PacketProcessor:
    """Parses raw Scapy packets into a more structured, displayable format."""
    def __init__(self):
        self.geoip_cache = {}  # Cache for GeoIP lookups
    
    def get_packet_summary(self, packet):
        """Extracts key information for the packet list (Treeview)."""
        summary_info = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip": "-",
            "dst_ip": "-",
            "protocol": "Unknown",
            "length": len(packet),
            "info": "",
            "src_port": "-",
            "dst_port": "-",
            "flags": ""
        }

        # Ethernet Layer
        if Ether in packet:
            summary_info["info"] += f"Eth({packet[Ether].src[:8]}... > {packet[Ether].dst[:8]}...) "

        # IP Layer
        if IP in packet:
            summary_info["src_ip"] = packet[IP].src
            summary_info["dst_ip"] = packet[IP].dst
            summary_info["protocol"] = packet[IP].proto
            protocol_counter[self.get_protocol_name(packet[IP].proto)] += 1
            global total_bytes_sniffed
            total_bytes_sniffed += len(packet)

            # Transport Layer
            if TCP in packet:
                summary_info["protocol"] = "TCP"
                summary_info["src_port"] = packet[TCP].sport
                summary_info["dst_port"] = packet[TCP].dport
                summary_info["flags"] = self.get_tcp_flags(packet[TCP])
                summary_info["info"] += f"TCP {summary_info['src_ip']}:{summary_info['src_port']} > {summary_info['dst_ip']}:{summary_info['dst_port']} [{summary_info['flags']}]"
                
                # Enhanced HTTP detection
                if (packet[TCP].dport in [80, 8080, 443] or packet[TCP].sport in [80, 8080, 443]):
                    if Raw in packet:
                        payload = packet[Raw].load
                        if b'HTTP' in payload:
                            if b'GET' in payload or b'POST' in payload:
                                summary_info["info"] += " HTTP Request"
                            elif b'200 OK' in payload or b'404' in payload:
                                summary_info["info"] += " HTTP Response"
                        
            elif UDP in packet:
                summary_info["protocol"] = "UDP"
                summary_info["src_port"] = packet[UDP].sport
                summary_info["dst_port"] = packet[UDP].dport
                summary_info["info"] += f"UDP {summary_info['src_ip']}:{summary_info['src_port']} > {summary_info['dst_ip']}:{summary_info['dst_port']}"
                
                # Enhanced DNS detection
                if DNS in packet:
                    if packet[DNS].qr == 0:  # Query
                        if packet[DNS].qdcount > 0:
                            summary_info["info"] += f" DNS Query: {packet[DNS].qd.qname.decode()}"
                    elif packet[DNS].qr == 1:  # Response
                        summary_info["info"] += f" DNS Response ({packet[DNS].ancount} answers)"
                        
            elif ICMP in packet:
                summary_info["protocol"] = "ICMP"
                summary_info["info"] += f"ICMP Type {packet[ICMP].type} Code {packet[ICMP].code}"
                
                # ICMP type descriptions
                icmp_types = {
                    0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request",
                    11: "Time Exceeded", 12: "Parameter Problem"
                }
                if packet[ICMP].type in icmp_types:
                    summary_info["info"] += f" ({icmp_types[packet[ICMP].type]})"
            else:
                summary_info["info"] += f"IP Protocol {packet[IP].proto}"

        # ARP Layer
        elif ARP in packet:
            summary_info["protocol"] = "ARP"
            summary_info["src_ip"] = packet[ARP].psrc
            summary_info["dst_ip"] = packet[ARP].pdst
            arp_ops = {1: "Request", 2: "Reply"}
            op_name = arp_ops.get(packet[ARP].op, "Unknown")
            summary_info["info"] = f"ARP {op_name}: {packet[ARP].psrc} is at {packet[ARP].hwsrc}"

        return summary_info

    def get_tcp_flags(self, tcp_layer):
        """Extract TCP flags as a readable string."""
        flags = []
        if tcp_layer.flags.F: flags.append("FIN")
        if tcp_layer.flags.S: flags.append("SYN")
        if tcp_layer.flags.R: flags.append("RST")
        if tcp_layer.flags.P: flags.append("PSH")
        if tcp_layer.flags.A: flags.append("ACK")
        if tcp_layer.flags.U: flags.append("URG")
        if tcp_layer.flags.E: flags.append("ECE")
        if tcp_layer.flags.C: flags.append("CWR")
        return ",".join(flags) if flags else "None"

    def get_protocol_name(self, proto_num):
        """Maps IP protocol numbers to common names."""
        protocols = {
            1: "ICMP", 6: "TCP", 17: "UDP", 27: "RDP", 89: "OSPF",
            47: "GRE", 50: "ESP", 51: "AH", 58: "IPv6-ICMP", 2: "IGMP",
            41: "IPv6", 132: "SCTP"
        }
        return protocols.get(proto_num, "Other")

    def get_detailed_packet_info(self, packet):
        """Generates a detailed, layered string representation of the packet."""
        details = []
        
        # Enhanced packet analysis
        details.append("=== PACKET ANALYSIS ===")
        details.append(f"Packet Length: {len(packet)} bytes")
        details.append(f"Layers: {' > '.join([layer.name for layer in packet.layers()])}")
        details.append("")
        
        # Layer-by-layer analysis
        for i, layer in enumerate(packet.layers()):
            layer_obj = packet.getlayer(i)
            details.append(f"--- Layer {i+1}: {layer.name} ---")
            details.append(layer_obj.show(dump=True))
            details.append("")
        
        # Security analysis
        if self.has_suspicious_patterns(packet):
            details.append("⚠️  SECURITY ALERT: Suspicious patterns detected!")
            details.append("")
        
        # Payload analysis
        if Raw in packet:
            payload = packet[Raw].load
            details.append("--- Payload Analysis ---")
            details.append(f"Payload Length: {len(payload)} bytes")
            if self.is_printable_payload(payload):
                details.append("Payload (Text):")
                details.append(payload.decode('utf-8', errors='replace'))
            else:
                details.append("Payload (Hex):")
                details.append(payload.hex())
            details.append("")
        
        return "\n".join(details)

    def has_suspicious_patterns(self, packet):
        """Check if packet contains suspicious patterns."""
        if Raw in packet:
            payload = packet[Raw].load.lower()
            suspicious_patterns = [
                b'select * from', b'union select', b'<script>', 
                b'javascript:', b'../../etc/passwd', b'cmd.exe'
            ]
            return any(pattern in payload for pattern in suspicious_patterns)
        return False

    def is_printable_payload(self, payload):
        """Check if payload is printable text."""
        try:
            decoded = payload.decode('utf-8')
            return all(c.isprintable() or c.isspace() for c in decoded)
        except:
            return False

    def get_packet_hex_dump(self, packet):
        """Generates an enhanced hexadecimal and ASCII dump of the packet."""
        hex_dump = []
        hex_dump.append("=== HEX DUMP ===")
        hex_dump.append(f"Total Length: {len(packet)} bytes")
        hex_dump.append("")
        
        # Enhanced hex dump with offset and ASCII representation
        data = bytes(packet)
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_dump.append(f"{i:08x}  {hex_part:<48} |{ascii_part}|")
        
        hex_dump.append("")
        hex_dump.append("=== SCAPY HEX DUMP ===")
        hex_dump.append(packet.hexdump())
        
        return "\n".join(hex_dump)

class NetworkTopology:
    """Analyzes network topology and creates visual representations."""
    def __init__(self):
        self.hosts = set()
        self.connections = defaultdict(set)
        self.protocols_by_host = defaultdict(set)
    
    def add_connection(self, src_ip, dst_ip, protocol):
        """Add a connection to the topology."""
        if src_ip != '-' and dst_ip != '-':
            self.hosts.add(src_ip)
            self.hosts.add(dst_ip)
            self.connections[src_ip].add(dst_ip)
            self.protocols_by_host[src_ip].add(protocol)
            self.protocols_by_host[dst_ip].add(protocol)
    
    def get_topology_summary(self):
        """Get a summary of the network topology."""
        return {
            'total_hosts': len(self.hosts),
            'total_connections': sum(len(conns) for conns in self.connections.values()),
            'most_active_host': max(self.connections.keys(), 
                                  key=lambda x: len(self.connections[x]), 
                                  default=None),
            'protocols': set().union(*self.protocols_by_host.values()) if self.protocols_by_host else set()
        }

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Advanced Network Security Analyzer")
        self.root.geometry("1600x900")
        self.root.configure(bg="#1a1a2e")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Initialize components
        self.db_manager = DatabaseManager()
        self.security_analyzer = SecurityAnalyzer(self.db_manager)
        self.network_topology = NetworkTopology()
        self.sniffer_engine = SnifferEngine(self.handle_sniffed_packet)
        self.packet_processor = PacketProcessor()
        
        # Configuration
        self.auto_scroll = tk.BooleanVar(value=True)
        self.enable_security_analysis = tk.BooleanVar(value=True)
        self.packet_limit = tk.IntVar(value=0)  # 0 = unlimited
        
        self.setup_ui()
        self.setup_styles()
        self.update_stats()
        self.load_interfaces()
        
        # Start bandwidth monitoring
        self.monitor_bandwidth()

    def setup_ui(self):
        """Setup the enhanced user interface."""
        # Title with enhanced styling
        title_frame = tk.Frame(self.root, bg="#1a1a2e")
        title_frame.pack(pady=(10, 0))
        
        title = tk.Label(title_frame, text="🔍 Advanced Network Security Analyzer", 
                        font=("Helvetica", 24, "bold"), bg="#1a1a2e", fg="#00d4ff")
        title.pack()
        
        subtitle = tk.Label(title_frame, text="Real-time Network Traffic Analysis & Security Monitoring", 
                           font=("Helvetica", 12), bg="#1a1a2e", fg="#888")
        subtitle.pack()

        # Enhanced Control Frame
        control_frame = ttk.Frame(self.root, padding="15")
        control_frame.pack(pady=10, fill=tk.X)

        # Row 1: Basic controls
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(control_frame, textvariable=self.interface_var, 
                                             state="readonly", width=20)
        self.interface_dropdown.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(control_frame, text="BPF Filter:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.filter_entry = ttk.Entry(control_frame, width=30)
        self.filter_entry.grid(row=0, column=3, padx=5, pady=5)
        self.filter_entry.insert(0, "ip")

        ttk.Label(control_frame, text="Packet Limit:").grid(row=0, column=4, padx=5, pady=5, sticky="w")
        self.packet_limit_entry = ttk.Entry(control_frame, textvariable=self.packet_limit, width=10)
        self.packet_limit_entry.grid(row=0, column=5, padx=5, pady=5)

        # Row 2: Action buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=1, column=0, columnspan=6, pady=10)

        self.start_button = ttk.Button(button_frame, text="▶ Start Capture", 
                                     command=self.start_sniffing, style='Success.TButton')
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="⏹ Stop Capture", 
                                    command=self.stop_sniffing, state=tk.DISABLED, style='Danger.TButton')
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.pause_button = ttk.Button(button_frame, text="⏸ Pause", 
                                     command=self.pause_sniffing, state=tk.DISABLED, style='Warning.TButton')
        self.pause_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(button_frame, text="🗑 Clear", command=self.clear_display)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.save_pcap_button = ttk.Button(button_frame, text="💾 Save PCAP", 
                                         command=self.save_packets_to_pcap)
        self.save_pcap_button.pack(side=tk.LEFT, padx=5)

        self.export_button = ttk.Button(button_frame, text="📊 Export Data", 
                                      command=self.export_analysis)
        self.export_button.pack(side=tk.LEFT, padx=5)

        # Row 3: Options
        options_frame = ttk.Frame(control_frame)
        options_frame.grid(row=2, column=0, columnspan=6, pady=5)

        ttk.Checkbutton(options_frame, text="Auto-scroll", variable=self.auto_scroll).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(options_frame, text="Security Analysis", variable=self.enable_security_analysis).pack(side=tk.LEFT, padx=10)

        # Main content area with notebook
        self.main_notebook = ttk.Notebook(self.root)
        self.main_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Packet Capture Tab
        self.setup_packet_capture_tab()
        
        # Network Analysis Tab
        self.setup_network_analysis_tab()
        
        # Security Dashboard Tab
        self.setup_security_dashboard_tab()

        # Status Bar
        self.setup_status_bar()

    def setup_packet_capture_tab(self):
        """Setup the packet capture tab."""
        capture_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(capture_frame, text="📡 Packet Capture")

        # Paned window for packet list and details
        paned_window = ttk.PanedWindow(capture_frame, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Packet List Frame
        packet_list_frame = ttk.Frame(paned_window)
        paned_window.add(packet_list_frame, weight=2)

        # Enhanced packet list with more columns
        columns = ("ID", "Time", "Protocol", "Source IP", "Src Port", "Destination IP", 
                  "Dst Port", "Length", "Flags", "Info")
        self.packet_tree = ttk.Treeview(packet_list_frame, columns=columns, show="headings", 
                                       selectmode="browse", height=15)
        
        # Configure columns
        column_widths = {"ID": 50, "Time": 100, "Protocol": 80, "Source IP": 120, 
                        "Src Port": 80, "Destination IP": 120, "Dst Port": 80, 
                        "Length": 80, "Flags": 100, "Info": 300}
        
        for col in columns:
            self.packet_tree.heading(col, text=col, anchor=tk.W)
            self.packet_tree.column(col, width=column_widths.get(col, 100), anchor=tk.W)

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(packet_list_frame, orient="vertical", command=self.packet_tree.yview)
        h_scrollbar = ttk.Scrollbar(packet_list_frame, orient="horizontal", command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # Details notebook
        details_notebook = ttk.Notebook(paned_window)
        paned_window.add(details_notebook, weight=1)

        # Packet Details Tab
        self.setup_packet_details_tab(details_notebook)
        
        # Hex Dump Tab
        self.setup_hex_dump_tab(details_notebook)

    def setup_packet_details_tab(self, parent):
        """Setup packet details tab."""
        detail_frame = ttk.Frame(parent)
        parent.add(detail_frame, text="📋 Packet Details")
        
        self.detail_text = tk.Text(detail_frame, bg="#1a1a2e", fg="#00ff00", 
                                  font=("Consolas", 10), wrap="word")
        detail_scrollbar = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_scrollbar.set)
        
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_hex_dump_tab(self, parent):
        """Setup hex dump tab."""
        hex_frame = ttk.Frame(parent)
        parent.add(hex_frame, text="🔍 Hex Dump")
        
        self.hex_text = tk.Text(hex_frame, bg="#1a1a2e", fg="#00ff00", 
                               font=("Consolas", 9), wrap="none")
        hex_v_scrollbar = ttk.Scrollbar(hex_frame, orient="vertical", command=self.hex_text.yview)
        hex_h_scrollbar = ttk.Scrollbar(hex_frame, orient="horizontal", command=self.hex_text.xview)
        self.hex_text.configure(yscrollcommand=hex_v_scrollbar.set, xscrollcommand=hex_h_scrollbar.set)
        
        self.hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hex_v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        hex_h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_network_analysis_tab(self):
        """Setup network analysis tab."""
        analysis_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(analysis_frame, text="📊 Network Analysis")

        # Statistics frame
        stats_frame = ttk.LabelFrame(analysis_frame, text="Network Statistics", padding="10")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)

        self.network_stats_text = tk.Text(stats_frame, height=10, bg="#1a1a2e", fg="#00d4ff", 
                                         font=("Consolas", 10))
        self.network_stats_text.pack(fill=tk.BOTH, expand=True)

        # Top talkers frame
        talkers_frame = ttk.LabelFrame(analysis_frame, text="Top Talkers", padding="10")
        talkers_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Top talkers treeview
        talker_columns = ("IP Address", "Packets Sent", "Bytes Sent", "Protocols", "Status")
        self.talkers_tree = ttk.Treeview(talkers_frame, columns=talker_columns, show="headings", height=8)
        
        for col in talker_columns:
            self.talkers_tree.heading(col, text=col)
            self.talkers_tree.column(col, width=120)
        
        talkers_scrollbar = ttk.Scrollbar(talkers_frame, orient="vertical", command=self.talkers_tree.yview)
        self.talkers_tree.configure(yscrollcommand=talkers_scrollbar.set)
        
        self.talkers_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        talkers_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_security_dashboard_tab(self):
        """Setup security dashboard tab."""
        security_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(security_frame, text="🛡️ Security Dashboard")

        # Security alerts frame
        alerts_frame = ttk.LabelFrame(security_frame, text="Security Alerts", padding="10")
        alerts_frame.pack(fill=tk.X, padx=5, pady=5)

        alert_columns = ("Timestamp", "IP Address", "Alert Type", "Severity", "Description")
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=alert_columns, show="headings", height=8)
        
        for col in alert_columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=150)
        
        alerts_scrollbar = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scrollbar.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alerts_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Suspicious IPs frame
        suspicious_frame = ttk.LabelFrame(security_frame, text="Suspicious IP Addresses", padding="10")
        suspicious_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.suspicious_text = tk.Text(suspicious_frame, bg="#2e1a1a", fg="#ff6b6b", 
                                      font=("Consolas", 10), height=8)
        suspicious_scrollbar = ttk.Scrollbar(suspicious_frame, orient="vertical", command=self.suspicious_text.yview)
        self.suspicious_text.configure(yscrollcommand=suspicious_scrollbar.set)
        
        self.suspicious_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        suspicious_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Security actions frame
        actions_frame = ttk.Frame(security_frame)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(actions_frame, text="🔍 Whois Lookup", command=self.whois_lookup).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="🚫 Block IP", command=self.block_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="📋 Export Security Report", command=self.export_security_report).pack(side=tk.LEFT, padx=5)

    def setup_status_bar(self):
        """Setup enhanced status bar."""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, pady=5)

        self.status_label = ttk.Label(status_frame, text="Status: Ready", font=("Consolas", 10))
        self.status_label.pack(side=tk.LEFT, padx=10)

        self.stats_label = ttk.Label(status_frame, text="", font=("Consolas", 10))
        self.stats_label.pack(side=tk.RIGHT, padx=10)

        # Progress bar for packet capture
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, 
                                          mode='determinate', length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=10)

    def setup_styles(self):
        """Setup enhanced TTK styles."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('Success.TButton', background='#27ae60', foreground='white')
        style.configure('Danger.TButton', background='#e74c3c', foreground='white')
        style.configure('Warning.TButton', background='#f39c12', foreground='white')
        style.configure('TLabel', background='#1a1a2e', foreground='white')
        style.configure('TFrame', background='#1a1a2e')
        style.configure('TLabelFrame', background='#1a1a2e', foreground='white')
        style.configure('TNotebook', background='#1a1a2e')
        style.configure('TNotebook.Tab', padding=[10, 5])

    def load_interfaces(self):
        """Load available network interfaces."""
        try:
            interfaces = get_if_list()
            self.interface_dropdown['values'] = interfaces
            if interfaces:
                self.interface_var.set(interfaces[0])
        except Exception as e:
            messagebox.showerror("Error", f"Could not list interfaces: {e}")

    def monitor_bandwidth(self):
        """Monitor bandwidth usage."""
        current_time = time.time()
        bandwidth_tracker.append((current_time, total_bytes_sniffed))
        
        # Calculate bandwidth over last 5 seconds
        if len(bandwidth_tracker) >= 2:
            recent_data = [x for x in bandwidth_tracker if current_time - x[0] <= 5]
            if len(recent_data) >= 2:
                time_diff = recent_data[-1][0] - recent_data[0][0]
                bytes_diff = recent_data[-1][1] - recent_data[0][1]
                if time_diff > 0:
                    bandwidth_bps = bytes_diff / time_diff
                    self.update_bandwidth_display(bandwidth_bps)
        
        self.root.after(1000, self.monitor_bandwidth)

    def update_bandwidth_display(self, bandwidth_bps):
        """Update bandwidth display in status bar."""
        bandwidth_text = self.format_bandwidth(bandwidth_bps)
        # This will be included in the stats update

    def format_bandwidth(self, bps):
        """Format bandwidth in human-readable format."""
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if bps < 1024.0:
                return f"{bps:.2f} {unit}"
            bps /= 1024.0
        return f"{bps:.2f} TB/s"

    def handle_sniffed_packet(self, packet, error=None):
        """Enhanced packet handler with security analysis."""
        if error:
            self.root.after(0, lambda: messagebox.showerror("Sniffing Error", error))
            self.root.after(0, self.stop_sniffing)
            return

        if not sniffing or not packet:
            return

        with packet_lock:
            # Process packet
            summary = self.packet_processor.get_packet_summary(packet)
            
            # Security analysis
            if self.enable_security_analysis.get():
                self.security_analyzer.analyze_packet(packet, summary)
            
            # Network topology tracking
            self.network_topology.add_connection(
                summary.get('src_ip', '-'), 
                summary.get('dst_ip', '-'), 
                summary.get('protocol', 'Unknown')
            )
            
            # Store in database
            self.db_manager.store_packet(summary)
            
            # Update GUI
            self.root.after(0, lambda: self.update_packet_display(summary, packet))

    def update_packet_display(self, summary, packet):
        """Update the packet display in GUI."""
        global packet_display_index
        
        item_id = f"pkt_{packet_display_index}"
        packet_display_index += 1

        # Color coding based on protocol
        tags = []
        if summary['protocol'] == 'TCP':
            tags.append('tcp')
        elif summary['protocol'] == 'UDP':
            tags.append('udp')
        elif summary['protocol'] == 'ICMP':
            tags.append('icmp')
        elif summary['protocol'] == 'ARP':
            tags.append('arp')
        
        # Security tagging
        if summary.get('src_ip') in suspicious_ips or summary.get('dst_ip') in suspicious_ips:
            tags.append('suspicious')

        values = (
            packet_display_index - 1,
            summary["timestamp"],
            summary["protocol"],
            summary["src_ip"],
            summary["src_port"],
            summary["dst_ip"],
            summary["dst_port"],
            summary["length"],
            summary.get("flags", ""),
            summary["info"][:100] + "..." if len(summary["info"]) > 100 else summary["info"]
        )

        self.packet_tree.insert("", "end", iid=item_id, values=values, tags=tags)
        
        # Configure tags for color coding
        self.packet_tree.tag_configure('tcp', background='#1a3d1a')
        self.packet_tree.tag_configure('udp', background='#1a1a3d')
        self.packet_tree.tag_configure('icmp', background='#3d1a1a')
        self.packet_tree.tag_configure('arp', background='#3d3d1a')
        self.packet_tree.tag_configure('suspicious', background='#5d1a1a', foreground='#ff6b6b')

        if self.auto_scroll.get():
            self.packet_tree.yview_moveto(1)

        # Update progress bar if packet limit is set
        if self.packet_limit.get() > 0:
            progress = (packet_display_index / self.packet_limit.get()) * 100
            self.progress_var.set(min(progress, 100))

        captured_packets.append({"id": item_id, "packet": packet})
        
        # Update network analysis
        self.update_network_analysis()
        self.update_security_dashboard()

    def update_network_analysis(self):
        """Update network analysis display."""
        if len(captured_packets) % 10 == 0:  # Update every 10 packets to reduce overhead
            topology_summary = self.network_topology.get_topology_summary()
            
            stats_text = f"""
Network Topology Summary:
- Total Hosts: {topology_summary['total_hosts']}
- Total Connections: {topology_summary['total_connections']}
- Most Active Host: {topology_summary['most_active_host'] or 'N/A'}
- Protocols Observed: {', '.join(topology_summary['protocols']) or 'None'}

Connection Statistics:
"""
            
            # Top talkers analysis
            host_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'protocols': set()})
            
            for pkt_data in captured_packets[-100:]:  # Last 100 packets
                summary = self.packet_processor.get_packet_summary(pkt_data['packet'])
                src_ip = summary.get('src_ip', '-')
                if src_ip != '-':
                    host_stats[src_ip]['packets'] += 1
                    host_stats[src_ip]['bytes'] += summary.get('length', 0)
                    host_stats[src_ip]['protocols'].add(summary.get('protocol', 'Unknown'))
            
            # Update top talkers tree
            self.talkers_tree.delete(*self.talkers_tree.get_children())
            for ip, stats in sorted(host_stats.items(), key=lambda x: x[1]['packets'], reverse=True)[:10]:
                status = "🚨 Suspicious" if ip in suspicious_ips else "✅ Normal"
                self.talkers_tree.insert("", "end", values=(
                    ip, stats['packets'], self.format_bytes(stats['bytes']),
                    ', '.join(stats['protocols']), status
                ))
            
            self.network_stats_text.delete('1.0', tk.END)
            self.network_stats_text.insert(tk.END, stats_text)

    def update_security_dashboard(self):
        """Update security dashboard."""
        # Update suspicious IPs display
        self.suspicious_text.delete('1.0', tk.END)
        if suspicious_ips:
            self.suspicious_text.insert(tk.END, "⚠️ SUSPICIOUS IP ADDRESSES DETECTED:\n\n")
            for ip in suspicious_ips:
                self.suspicious_text.insert(tk.END, f"🚨 {ip}\n")
                # Add connection count
                conn_count = connection_tracker.get(ip, 0)
                self.suspicious_text.insert(tk.END, f"   └─ Connections: {conn_count}\n")
        else:
            self.suspicious_text.insert(tk.END, "✅ No suspicious activity detected.")

    def on_packet_select(self, event):
        """Handle packet selection for detailed view."""
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return

        item_id = selected_item[0]
        selected_packet_obj = next((p for p in captured_packets if p["id"] == item_id), None)

        if selected_packet_obj:
            packet = selected_packet_obj["packet"]
            
            # Display detailed information
            detail_info = self.packet_processor.get_detailed_packet_info(packet)
            self.detail_text.config(state=tk.NORMAL)
            self.detail_text.delete('1.0', tk.END)
            self.detail_text.insert(tk.END, detail_info)
            self.detail_text.config(state=tk.DISABLED)

            # Display enhanced hex dump
            hex_dump_info = self.packet_processor.get_packet_hex_dump(packet)
            self.hex_text.config(state=tk.NORMAL)
            self.hex_text.delete('1.0', tk.END)
            self.hex_text.insert(tk.END, hex_dump_info)
            self.hex_text.config(state=tk.DISABLED)

    def start_sniffing(self):
        """Start packet capture with enhanced features."""
        global sniffing, sniff_thread, captured_packets, packet_display_index
        global protocol_counter, total_bytes_sniffed
        
        if sniffing:
            return

        # Reset state
        sniffing = True
        captured_packets.clear()
        packet_display_index = 0
        protocol_counter.clear()
        total_bytes_sniffed = 0
        suspicious_ips.clear()
        connection_tracker.clear()
        
        selected_iface = self.interface_var.get()
        bpf_filter = self.filter_entry.get()
        packet_limit = self.packet_limit.get()

        if not selected_iface:
            messagebox.showwarning("Warning", "Please select a network interface.")
            sniffing = False
            return

        self.status_label.config(text=f"Status: Capturing on {selected_iface}...")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.NORMAL)
        
        # Start capture thread
        sniff_thread = threading.Thread(
            target=lambda: self.sniffer_engine.start_sniff(selected_iface, bpf_filter, packet_limit)
        )
        sniff_thread.daemon = True
        sniff_thread.start()

    def stop_sniffing(self):
        """Stop packet capture."""
        global sniffing
        if not sniffing:
            return

        self.sniffer_engine.stop_sniff()
        sniffing = False

        self.status_label.config(text="Status: Stopped")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.DISABLED)
        
        # Show capture statistics
        stats = self.sniffer_engine.get_capture_stats()
        if stats:
            messagebox.showinfo("Capture Complete", 
                              f"Captured {stats['packets']} packets in {stats['duration']:.2f} seconds\n"
                              f"Average: {stats['pps']:.2f} packets/second")

    def pause_sniffing(self):
        """Pause/resume packet capture."""
        # This is a simplified pause - in a real implementation, you'd need more sophisticated control
        pass

    def clear_display(self):
        """Clear all displays and reset counters."""
        global captured_packets, packet_display_index, protocol_counter, total_bytes_sniffed
        
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.config(state=tk.DISABLED)
        self.hex_text.config(state=tk.NORMAL)
        self.hex_text.delete('1.0', tk.END)
        self.hex_text.config(state=tk.DISABLED)
        self.network_stats_text.delete('1.0', tk.END)
        self.suspicious_text.delete('1.0', tk.END)
        self.talkers_tree.delete(*self.talkers_tree.get_children())
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        
        captured_packets.clear()
        packet_display_index = 0
        protocol_counter.clear()
        total_bytes_sniffed = 0
        suspicious_ips.clear()
        connection_tracker.clear()
        self.progress_var.set(0)

    def save_packets_to_pcap(self):
        """Save captured packets to PCAP file."""
        if not captured_packets:
            messagebox.showwarning("No Packets", "No packets captured yet.")
            return

        default_filename = datetime.datetime.now().strftime("capture_%Y%m%d_%H%M%S.pcap")
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            initialfile=default_filename,
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        if file_path:
            try:
                packets_to_save = [p["packet"] for p in captured_packets]
                wrpcap(file_path, packets_to_save)
                messagebox.showinfo("Success", f"Saved {len(packets_to_save)} packets to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")

    def export_analysis(self):
        """Export network analysis to JSON."""
        if not captured_packets:
            messagebox.showwarning("No Data", "No data to export.")
            return

        export_data = {
            'capture_info': {
                'timestamp': datetime.datetime.now().isoformat(),
                'total_packets': len(captured_packets),
                'total_bytes': total_bytes_sniffed,
                'protocols': dict(protocol_counter)
            },
            'network_topology': self.network_topology.get_topology_summary(),
            'suspicious_ips': list(suspicious_ips),
            'top_talkers': dict(connection_tracker)
        }

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                messagebox.showinfo("Success", f"Analysis exported to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")

    def whois_lookup(self):
        """Perform WHOIS lookup on selected IP."""
        if not self.talkers_tree.selection():
            messagebox.showinfo("Info", "Please select an IP address from the top talkers list.")
            return
        
        item = self.talkers_tree.selection()[0]
        ip_address = self.talkers_tree.item(item)['values'][0]
        
        # Open web browser for WHOIS lookup
        webbrowser.open(f"https://whois.net/ip/{ip_address}")

    def block_ip(self):
        """Block selected IP address (demonstration)."""
        if not self.talkers_tree.selection():
            messagebox.showinfo("Info", "Please select an IP address from the top talkers list.")
            return
        
        item = self.talkers_tree.selection()[0]
        ip_address = self.talkers_tree.item(item)['values'][0]
        
        # This would integrate with firewall rules in a real implementation
        result = messagebox.askyesno("Block IP", f"Block IP address {ip_address}?\n\n"
                                   "Note: This is a demonstration. In a real implementation, "
                                   "this would add firewall rules.")
        if result:
            messagebox.showinfo("Blocked", f"IP {ip_address} would be blocked.")

    def export_security_report(self):
        """Export security analysis report."""
        report_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'suspicious_ips': list(suspicious_ips),
            'connection_stats': dict(connection_tracker),
            'total_packets_analyzed': len(captured_packets),
            'security_alerts': len(suspicious_ips)
        }

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt")]
        )

        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(report_data, f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        f.write("NETWORK SECURITY ANALYSIS REPORT\n")
                        f.write("=" * 40 + "\n\n")
                        f.write(f"Generated: {report_data['timestamp']}\n")
                        f.write(f"Packets Analyzed: {report_data['total_packets_analyzed']}\n")
                        f.write(f"Security Alerts: {report_data['security_alerts']}\n\n")
                        f.write("SUSPICIOUS IP ADDRESSES:\n")
                        for ip in report_data['suspicious_ips']:
                            f.write(f"- {ip} ({connection_tracker.get(ip, 0)} connections)\n")
                
                messagebox.showinfo("Success", f"Security report exported to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {e}")

    def update_stats(self):
        """Update statistics display."""
        stats_text = (
            f"TCP: {protocol_counter['TCP']} | "
            f"UDP: {protocol_counter['UDP']} | "
            f"ICMP: {protocol_counter['ICMP']} | "
            f"ARP: {protocol_counter['ARP']} | "
            f"Other: {protocol_counter['Other']} | "
            f"Total: {self.format_bytes(total_bytes_sniffed)} | "
            f"Suspicious: {len(suspicious_ips)}"
        )
        self.stats_label.config(text=stats_text)
        self.root.after(1000, self.update_stats)

    def format_bytes(self, num_bytes):
        """Format bytes in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.2f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.2f} TB"

    def on_closing(self):
        """Handle application closing."""
        if sniffing:
            if messagebox.askokcancel("Quit", "Capture is active. Stop and quit?"):
                self.stop_sniffing()
                self.root.destroy()
        else:
            self.root.destroy()

# Main execution
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
