import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import threading
from collections import defaultdict

# Global counters and state
protocol_counter = defaultdict(int)
sniffing = False
sniff_thread = None

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🕵️ Network Packet Sniffer")
        self.root.geometry("1100x700")
        self.root.configure(bg="#1e1e2f")

        # Title
        title = tk.Label(root, text="Live Network Packet Sniffer", font=("Helvetica", 18, "bold"), bg="#1e1e2f", fg="#00ffcc")
        title.pack(pady=10)

        # Packet display area
        self.text = tk.Text(root, height=28, width=130, bg="black", fg="lime", font=("Courier New", 10))
        self.text.pack(pady=10)

        # Protocol stats label
        self.stats_label = tk.Label(root, text="", font=("Consolas", 12), fg="#00ace6", bg="#1e1e2f")
        self.stats_label.pack(pady=5)

        # Status label
        self.status_label = tk.Label(root, text="Status: Not sniffing", font=("Consolas", 11, "italic"), fg="red", bg="#1e1e2f")
        self.status_label.pack(pady=2)

        # Button frame
        btn_frame = tk.Frame(root, bg="#1e1e2f")
        btn_frame.pack(pady=10)

        # Start button
        self.start_button = tk.Button(btn_frame, text="▶ Start Sniffing", command=self.start_sniffing, bg="green", fg="white", font=("Arial", 12), width=20)
        self.start_button.grid(row=0, column=0, padx=10)

        # Stop button
        self.stop_button = tk.Button(btn_frame, text="■ Stop Sniffing", command=self.stop_sniffing, bg="red", fg="white", font=("Arial", 12), width=20, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=10)

    def update_stats(self):
        stats = (
            f"TCP: {protocol_counter['TCP']} | "
            f"UDP: {protocol_counter['UDP']} | "
            f"ICMP: {protocol_counter['ICMP']} | "
            f"Other: {protocol_counter['Other']}"
        )
        self.stats_label.config(text=stats)

    def format_payload(self, raw):
        try:
            decoded = raw.load.decode('utf-8', errors='replace')
            return decoded[:50]
        except Exception:
            return str(raw.load[:50])

    def display_packet(self, packet):
        if not sniffing:
            return

        if IP in packet:
            proto_num = packet[IP].proto
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Default values
            src_port = dst_port = "-"
            payload = ""

            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol_counter['TCP'] += 1
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol_counter['UDP'] += 1
            elif ICMP in packet:
                protocol = "ICMP"
                protocol_counter['ICMP'] += 1
            else:
                protocol = f"Other({proto_num})"
                protocol_counter['Other'] += 1

            # Get payload if available
            if Raw in packet:
                payload = self.format_payload(packet[Raw])

            # Display in GUI
            line = f"[{protocol}] {src_ip}:{src_port} → {dst_ip}:{dst_port}\n"
            self.text.insert(tk.END, line)
            if payload:
                self.text.insert(tk.END, f"    📦 Payload: {payload}\n")
            self.text.see(tk.END)
            self.update_stats()

    def start_sniffing(self):
        global sniffing, sniff_thread
        sniffing = True
        protocol_counter.clear()
        self.text.delete('1.0', tk.END)
        self.status_label.config(text="Status: Sniffing...", fg="lime")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        sniff_thread = threading.Thread(target=lambda: sniff(prn=self.display_packet, filter="ip", store=False))
        sniff_thread.daemon = True
        sniff_thread.start()

    def stop_sniffing(self):
        global sniffing
        sniffing = False
        self.status_label.config(text="Status: Stopped", fg="red")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
