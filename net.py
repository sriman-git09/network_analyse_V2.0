import threading
import socket
import uuid
import csv
import requests
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, get_if_list

# ---------------- GLOBAL VARIABLES ---------------- #

sniffing = False
packet_count = 0
sniffer_thread = None

danger_ports = [23, 445, 3389, 4444, 21]

# ---------------- SYSTEM INFO FUNCTIONS ---------------- #

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "Unavailable"

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return "No Internet"

def get_mac():
    mac = uuid.getnode()
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0,12,2))

# ---------------- PACKET HANDLER ---------------- #

def packet_handler(packet):
    global packet_count

    if not sniffing:
        return

    if IP in packet:
        packet_count += 1

        time_now = datetime.now().strftime("%H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)

        src_port = "-"
        dst_port = "-"
        protocol = "Other"
        tag = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if dst_port in danger_ports:
                tag = "danger"

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        root.after(0, update_gui,
                   packet_count, time_now,
                   src_ip, src_port,
                   dst_ip, dst_port,
                   protocol, size, tag)

# ---------------- GUI UPDATE ---------------- #

def update_gui(no, time, src, sport, dst, dport, proto, size, tag):
    packet_table.insert("", "end",
                        values=(no, time, src, sport,
                                dst, dport, proto, size),
                        tags=(tag,))
    counter_label.config(text=f"Packets Captured: {no}")

# ---------------- SNIFF CONTROL ---------------- #

def stop_filter(packet):
    return not sniffing

def start_sniffer():
    sniff(
        iface=interface_combo.get(),
        prn=packet_handler,
        store=False,
        stop_filter=stop_filter,
        filter=filter_entry.get()
    )

def start_sniffing():
    global sniffing, sniffer_thread

    if sniffing:
        return

    sniffing = True
    status_label.config(text="Sniffing Active", fg="green")

    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="Sniffing Stopped", fg="red")

# ---------------- CSV EXPORT ---------------- #

def save_to_csv():
    with open("captured_packets.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(columns)
        for row in packet_table.get_children():
            writer.writerow(packet_table.item(row)["values"])

# ---------------- GUI DESIGN ---------------- #

root = tk.Tk()
root.title("Network Packet Analyzer v2.0")
root.geometry("1100x650")
root.configure(bg="#0f172a")

tk.Label(root,
         text="Network Packet Analyzer v2.0",
         font=("Segoe UI", 20, "bold"),
         bg="#0f172a", fg="white").pack(pady=10)

tk.Label(root,
         text="Developed by: Sriman Kundu | Educational Use Only",
         font=("Segoe UI", 9),
         bg="#0f172a", fg="gray").pack()

# ---------------- SYSTEM INFO PANEL ---------------- #

info_frame = tk.LabelFrame(root,
                           text="My System Info",
                           bg="#0f172a",
                           fg="white")
info_frame.pack(pady=10)

tk.Label(info_frame,
         text=f"Hostname: {socket.gethostname()}",
         bg="#0f172a", fg="cyan").pack()

tk.Label(info_frame,
         text=f"Local IP: {get_local_ip()}",
         bg="#0f172a", fg="cyan").pack()

tk.Label(info_frame,
         text=f"Public IP: {get_public_ip()}",
         bg="#0f172a", fg="cyan").pack()

tk.Label(info_frame,
         text=f"MAC Address: {get_mac()}",
         bg="#0f172a", fg="cyan").pack()

# ---------------- INTERFACE & FILTER ---------------- #

control_frame = tk.Frame(root, bg="#0f172a")
control_frame.pack(pady=10)

tk.Label(control_frame,
         text="Interface:",
         bg="#0f172a", fg="white").pack(side="left")

interfaces = get_if_list()
interface_combo = ttk.Combobox(control_frame,
                               values=interfaces,
                               width=30)
interface_combo.pack(side="left", padx=5)
interface_combo.current(0)

tk.Label(control_frame,
         text="Filter:",
         bg="#0f172a", fg="white").pack(side="left")

filter_entry = tk.Entry(control_frame, width=20)
filter_entry.insert(0, "ip")
filter_entry.pack(side="left", padx=5)

# ---------------- BUTTONS ---------------- #

btn_frame = tk.Frame(root, bg="#0f172a")
btn_frame.pack(pady=10)

tk.Button(btn_frame,
          text="Start Sniffing",
          bg="green", fg="white",
          width=15,
          command=start_sniffing).pack(side="left", padx=10)

tk.Button(btn_frame,
          text="Stop Sniffing",
          bg="red", fg="white",
          width=15,
          command=stop_sniffing).pack(side="left", padx=10)

tk.Button(btn_frame,
          text="Export CSV",
          bg="blue", fg="white",
          width=15,
          command=save_to_csv).pack(side="left", padx=10)

counter_label = tk.Label(root,
                         text="Packets Captured: 0",
                         bg="#0f172a", fg="cyan")
counter_label.pack()

status_label = tk.Label(root,
                        text="Sniffing Stopped",
                        bg="#0f172a", fg="red")
status_label.pack(pady=5)

# ---------------- TABLE ---------------- #

columns = ("No", "Time", "Source IP", "Src Port",
           "Destination IP", "Dst Port",
           "Protocol", "Size")

packet_table = ttk.Treeview(root,
                            columns=columns,
                            show="headings",
                            height=15)

for col in columns:
    packet_table.heading(col, text=col)
    packet_table.column(col, width=130)

packet_table.tag_configure("danger", background="red")

packet_table.pack(pady=10)

root.mainloop()
                                   
