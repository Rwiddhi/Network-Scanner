import tkinter as tk
from tkinter import scrolledtext
from scapy.all import ICMP, IP, sr1, TCP, UDP

# Function to perform an ICMP ping
def icmp_ping(host):
    packet = IP(dst=host)/ICMP()
    reply = sr1(packet, timeout=1, verbose=0)
    if reply:
        return True
    else:
        return False

# Function to scan TCP ports
def tcp_scan(host, ports):
    open_ports = []
    for port in ports:
        packet = IP(dst=host)/TCP(dport=port, flags='S')
        reply = sr1(packet, timeout=1, verbose=0)
        if reply and reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
    return open_ports

# Function to scan UDP ports
def udp_scan(host, ports):
    open_ports = []
    for port in ports:
        packet = IP(dst=host)/UDP(dport=port)
        reply = sr1(packet, timeout=1, verbose=0)
        if reply is None:
            open_ports.append(port)
    return open_ports

# Function to scan the network
def scan_network():
    host = host_entry.get()
    result_text.delete(1.0, tk.END)

    result_text.insert(tk.END, f"Scanning host: {host}\n")

    # ICMP Ping
    result_text.insert(tk.END, "Performing ICMP Ping...\n")
    if icmp_ping(host):
        result_text.insert(tk.END, "Host is up\n")
    else:
        result_text.insert(tk.END, "Host is down\n")
        return

    # TCP Port Scan
    result_text.insert(tk.END, "Scanning TCP ports...\n")
    tcp_ports = [22, 23, 80, 443, 8080]
    open_tcp_ports = tcp_scan(host, tcp_ports)
    result_text.insert(tk.END, f"Open TCP ports: {open_tcp_ports}\n")

    # UDP Port Scan
    result_text.insert(tk.END, "Scanning UDP ports...\n")
    udp_ports = [53, 67, 68, 123]
    open_udp_ports = udp_scan(host, udp_ports)
    result_text.insert(tk.END, f"Open UDP ports: {open_udp_ports}\n")

# Create the main window
root = tk.Tk()
root.title("Simple Network Scanner")

# Host entry
tk.Label(root, text="Host:").grid(row=0, column=0, padx=5, pady=5)
host_entry = tk.Entry(root)
host_entry.grid(row=0, column=1, padx=5, pady=5)

# Scan button
scan_button = tk.Button(root, text="Scan", command=scan_network)
scan_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

# Result text area
result_text = scrolledtext.ScrolledText(root, width=50, height=15)
result_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

# Run the main event loop
root.mainloop()


