import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import ipaddress
import subprocess
import platform
import concurrent.futures
import socket
import threading
import random
import string
import secrets
from datetime import datetime
from typing import Tuple

class SubnetCalculatorTab:
    """
    Logic and UI for the Subnet Calculator Tab.
    """
    def __init__(self, parent):
        self.parent = parent
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.parent, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title = ttk.Label(main_frame, text="Subnet Calculator", 
                         font=('Arial', 16, 'bold'))
        title.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        ttk.Label(main_frame, text="IP Address:", font=('Arial', 10, 'bold')).grid(
            row=1, column=0, sticky=tk.W, pady=5)
        self.ip_entry = ttk.Entry(main_frame, width=30, font=('Arial', 10))
        self.ip_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        self.ip_entry.insert(0, "192.168.1.10")
        
        ttk.Label(main_frame, text="Subnet Mask / CIDR:", font=('Arial', 10, 'bold')).grid(
            row=2, column=0, sticky=tk.W, pady=5)
        self.mask_entry = ttk.Entry(main_frame, width=30, font=('Arial', 10))
        self.mask_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        self.mask_entry.insert(0, "24")
        
        info_label = ttk.Label(main_frame, 
                              text="Enter CIDR (e.g., 24) or subnet mask (e.g., 255.255.255.0)",
                              font=('Arial', 8), foreground='gray')
        info_label.grid(row=3, column=0, columnspan=2, pady=(0, 10))
        
        calc_button = ttk.Button(main_frame, text="Calculate", command=self.calculate)
        calc_button.grid(row=4, column=0, columnspan=2, pady=10)
        
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="15")
        results_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        self.result_labels = {}
        labels = [
            ("IP Address:", "ip"),
            ("Network Address:", "network"),
            ("Broadcast Address:", "broadcast"),
            ("Subnet Mask:", "netmask"),
            ("CIDR Notation:", "cidr"),
            ("Wildcard Mask:", "wildcard"),
            ("First Usable IP:", "first_ip"),
            ("Last Usable IP:", "last_ip"),
            ("Total Hosts:", "total_hosts"),
            ("Usable Hosts:", "usable_hosts"),
            ("IP Class:", "ip_class")
        ]
        
        for idx, (label_text, key) in enumerate(labels):
            ttk.Label(results_frame, text=label_text, 
                     font=('Arial', 9, 'bold')).grid(row=idx, column=0, 
                                                      sticky=tk.W, pady=3)
            self.result_labels[key] = ttk.Label(results_frame, text="—", 
                                               font=('Arial', 9))
            self.result_labels[key].grid(row=idx, column=1, sticky=tk.W, 
                                        padx=(10, 0), pady=3)
        
        clear_button = ttk.Button(main_frame, text="Clear", command=self.clear_results)
        clear_button.grid(row=6, column=0, columnspan=2, pady=10)
        
    def calculate(self):
        try:
            ip_input = self.ip_entry.get().strip()
            mask_input = self.mask_entry.get().strip()
            
            if '.' in mask_input:
                ip_str = f"{ip_input}/{self.cidr_from_netmask(mask_input)}"
            else:
                ip_str = f"{ip_input}/{mask_input}"
            
            network = ipaddress.IPv4Network(ip_str, strict=False)
            ip = ipaddress.IPv4Address(ip_input)
            
            total_hosts = network.num_addresses
            usable_hosts = total_hosts - 2 if total_hosts > 2 else 0
            
            first_ip = network.network_address + 1 if usable_hosts > 0 else "N/A"
            last_ip = network.broadcast_address - 1 if usable_hosts > 0 else "N/A"
            
            ip_class = self.get_ip_class(ip)
            wildcard = self.get_wildcard_mask(network.netmask)
            
            self.result_labels['ip'].config(text=str(ip))
            self.result_labels['network'].config(text=str(network.network_address))
            self.result_labels['broadcast'].config(text=str(network.broadcast_address))
            self.result_labels['netmask'].config(text=str(network.netmask))
            self.result_labels['cidr'].config(text=f"/{network.prefixlen}")
            self.result_labels['wildcard'].config(text=wildcard)
            self.result_labels['first_ip'].config(text=str(first_ip))
            self.result_labels['last_ip'].config(text=str(last_ip))
            self.result_labels['total_hosts'].config(text=str(total_hosts))
            self.result_labels['usable_hosts'].config(text=str(usable_hosts))
            self.result_labels['ip_class'].config(text=ip_class)
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def cidr_from_netmask(self, netmask):
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])
    
    def get_wildcard_mask(self, netmask):
        octets = str(netmask).split('.')
        wildcard_octets = [str(255 - int(octet)) for octet in octets]
        return '.'.join(wildcard_octets)
    
    def get_ip_class(self, ip):
        first_octet = int(str(ip).split('.')[0])
        if 1 <= first_octet <= 126: return "A"
        elif 128 <= first_octet <= 191: return "B"
        elif 192 <= first_octet <= 223: return "C"
        elif 224 <= first_octet <= 239: return "D (Multicast)"
        elif 240 <= first_octet <= 255: return "E (Experimental)"
        return "Unknown"
    
    def clear_results(self):
        for label in self.result_labels.values():
            label.config(text="—")
        self.ip_entry.delete(0, tk.END)
        self.mask_entry.delete(0, tk.END)
        self.ip_entry.insert(0, "192.168.1.10")
        self.mask_entry.insert(0, "24")


class NetworkScannerTab:
    """
    Logic and UI for the Ping Scanner Tab.
    """
    def __init__(self, parent):
        self.parent = parent
        self.scanning = False
        self.alive_hosts = []
        self.dns_results = {}
        self.current_network = ""
        
        self.setup_ui()
        
    def setup_ui(self):
        header_frame = ttk.Frame(self.parent, padding="10")
        header_frame.pack(fill=tk.X)
        
        title_label = ttk.Label(header_frame, text="Network Ping Scanner", font=("Arial", 16, "bold"))
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, text="Scan any network from /0 to /32 subnet mask", font=("Arial", 9))
        subtitle_label.pack()
        
        input_frame = ttk.LabelFrame(self.parent, text="Network Configuration", padding="10")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Network Address:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.network_entry = ttk.Entry(input_frame, width=30, font=("Arial", 10))
        self.network_entry.grid(row=0, column=1, padx=5)
        self.network_entry.insert(0, "192.168.1.0")
        ttk.Label(input_frame, text="(e.g., 192.168.1.0)").grid(row=0, column=2, sticky=tk.W, padx=5)
        
        ttk.Label(input_frame, text="Subnet Mask:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.subnet_var = tk.StringVar(value="24")
        subnet_spinbox = ttk.Spinbox(input_frame, from_=0, to=32, textvariable=self.subnet_var, width=10)
        subnet_spinbox.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(input_frame, text="(/0 to /32)").grid(row=1, column=2, sticky=tk.W, padx=5)
        
        ttk.Label(input_frame, text="Max Workers:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.workers_var = tk.StringVar(value="50")
        workers_spinbox = ttk.Spinbox(input_frame, from_=1, to=100, textvariable=self.workers_var, width=10)
        workers_spinbox.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        button_frame = ttk.Frame(self.parent, padding="10")
        button_frame.pack(fill=tk.X)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan, width=15)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED, width=15)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.dns_button = ttk.Button(button_frame, text="DNS Lookup", command=self.perform_dns_lookup, state=tk.DISABLED, width=15)
        self.dns_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(button_frame, text="Save Results", command=self.save_results, state=tk.DISABLED, width=15)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results, width=15)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        progress_frame = ttk.LabelFrame(self.parent, text="Scan Progress", padding="10")
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100, length=300)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="Ready to scan", font=("Arial", 9))
        self.status_label.pack()
        
        results_frame = ttk.LabelFrame(self.parent, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, width=80, height=20, font=("Courier", 9), wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        self.results_text.tag_config("header", foreground="blue", font=("Courier", 9, "bold"))
        self.results_text.tag_config("alive", foreground="green")
        self.results_text.tag_config("info", foreground="black")
        self.results_text.tag_config("error", foreground="red")
        self.results_text.tag_config("dns", foreground="purple")
        
        stats_frame = ttk.Frame(self.parent, padding="10")
        stats_frame.pack(fill=tk.X)
        self.stats_label = ttk.Label(stats_frame, text="Total Hosts Alive: 0 | Scanned: 0/0", font=("Arial", 10, "bold"))
        self.stats_label.pack()
        
    def log_message(self, message, tag="info"):
        self.results_text.insert(tk.END, message + "\n", tag)
        self.results_text.see(tk.END)
        self.parent.update_idletasks()
        
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.alive_hosts = []
        self.dns_results = {}
        self.stats_label.config(text="Total Hosts Alive: 0 | Scanned: 0/0")
        self.progress_var.set(0)
        self.status_label.config(text="Ready to scan")
        self.dns_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        
    def start_scan(self):
        network_input = self.network_entry.get().strip()
        if not network_input:
            messagebox.showerror("Error", "Please enter a network address")
            return
        
        if '/' in network_input:
            network_input = network_input.split('/')[0]
        
        subnet_mask = self.subnet_var.get()
        network_input = f"{network_input}/{subnet_mask}"
        
        try:
            test_net = ipaddress.IPv4Network(network_input, strict=False)
            host_count = test_net.num_addresses - 2
            
            if test_net.prefixlen < 20: 
                response = messagebox.askyesno("Large Network Warning", 
                    f"This network has {host_count:,} hosts.\nContinue anyway?")
                if not response: return
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid network address: {e}")
            return
        
        self.current_network = network_input
        self.scanning = True
        self.alive_hosts = []
        self.dns_results = {}
        
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.dns_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.clear_results()
        
        threading.Thread(target=self.run_scan, daemon=True).start()
        
    def stop_scan(self):
        self.scanning = False
        self.status_label.config(text="Scan stopped by user")
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
    def run_scan(self):
        try:
            net = ipaddress.IPv4Network(self.current_network, strict=False)
            hosts = list(net.hosts())
            total_hosts = len(hosts)
            
            if net.prefixlen == 32:
                hosts = [net.network_address]
                total_hosts = 1
            elif net.prefixlen == 31:
                hosts = [net.network_address, net.broadcast_address]
                total_hosts = 2
            
            max_workers = int(self.workers_var.get())
            
            self.log_message(f"{'='*60}", "header")
            self.log_message(f"Scanning {total_hosts} hosts in {net}", "header")
            self.log_message(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "header")
            self.log_message(f"{'='*60}\n", "header")
            
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_ip = {executor.submit(self.ping_host, str(ip)): ip for ip in hosts}
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    if not self.scanning:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    
                    ip, is_alive = future.result()
                    completed += 1
                    
                    if is_alive:
                        self.alive_hosts.append(ip)
                        self.log_message(f"[✓] {ip} is ALIVE", "alive")
                    
                    progress = (completed / total_hosts) * 100
                    self.progress_var.set(progress)
                    self.status_label.config(text=f"Scanning... {completed}/{total_hosts} hosts checked")
                    self.stats_label.config(text=f"Total Hosts Alive: {len(self.alive_hosts)} | Scanned: {completed}/{total_hosts}")
            
            if self.scanning:
                self.log_message("\n" + "="*60, "header")
                self.log_message("Scan Complete!", "header")
                self.log_message(f"Total hosts alive: {len(self.alive_hosts)}", "info")
                
                if self.alive_hosts:
                    self.dns_button.config(state=tk.NORMAL)
                    self.save_button.config(state=tk.NORMAL)
                else:
                    self.log_message("\nNo hosts responded.", "info")
                
                self.status_label.config(text=f"Scan complete - {len(self.alive_hosts)} hosts found")
            
        except Exception as e:
            self.log_message(f"Error during scan: {e}", "error")
        finally:
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def ping_host(self, ip: str, timeout: int = 1) -> Tuple[str, bool]:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        command = ['ping', param, '1', timeout_param, str(timeout), ip]
        
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 1)
            return (ip, output.returncode == 0)
        except:
            return (ip, False)
            
    def perform_dns_lookup(self):
        if not self.alive_hosts: return
        self.dns_button.config(state=tk.DISABLED)
        self.log_message("\n" + "="*60, "header")
        self.log_message("Performing DNS Lookups...", "header")
        threading.Thread(target=self.run_dns_lookup, daemon=True).start()
        
    def run_dns_lookup(self):
        total = len(self.alive_hosts)
        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {executor.submit(self.lookup_dns, ip): ip for ip in self.alive_hosts}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip, hostname = future.result()
                self.dns_results[ip] = hostname
                completed += 1
                if hostname != "N/A":
                    self.log_message(f"[DNS] {ip} → {hostname}", "dns")
                self.status_label.config(text=f"DNS lookup: {completed}/{total}")
        
        resolved = sum(1 for h in self.dns_results.values() if h != 'N/A')
        self.log_message(f"\nDNS lookups complete: {resolved}/{total} resolved", "info")
        
        self.log_message("\n" + "="*60, "header")
        self.log_message(f"{'IP Address':<20} {'Hostname'}", "info")
        self.log_message("-" * 60, "info")
        
        for host in sorted(self.alive_hosts, key=lambda x: ipaddress.IPv4Address(x)):
            hostname = self.dns_results.get(host, "N/A")
            self.log_message(f"{host:<20} {hostname}", "dns")
            
        self.dns_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        
    def lookup_dns(self, ip: str) -> Tuple[str, str]:
        try:
            return (ip, socket.gethostbyaddr(ip)[0])
        except:
            return (ip, "N/A")
            
    def save_results(self):
        if not self.alive_hosts: return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"scan_{timestamp}.txt")
        if not filename: return
        
        try:
            with open(filename, 'w') as f:
                f.write(f"Network Scan Results - {self.current_network}\n")
                f.write(f"Date: {datetime.now()}\n")
                f.write("="*40 + "\n\n")
                for host in sorted(self.alive_hosts, key=lambda x: ipaddress.IPv4Address(x)):
                    hostname = self.dns_results.get(host, "N/A")
                    f.write(f"{host:<20} {hostname}\n")
            messagebox.showinfo("Success", f"Saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")


class PortScannerTab:
    """
    Logic and UI for the Port Scanner Tab.
    """
    def __init__(self, parent):
        self.parent = parent
        self.scanning = False
        
        self.create_widgets()

    def create_widgets(self):
        # Header
        header_frame = ttk.Frame(self.parent, padding="10")
        header_frame.pack(fill=tk.X)
        
        ttk.Label(header_frame, text="Port Scanner", font=("Arial", 16, "bold")).pack()
        ttk.Label(header_frame, text="Scan specific TCP ports on a target host", font=("Arial", 9)).pack()

        # Input Frame
        input_frame = ttk.LabelFrame(self.parent, text="Target Configuration", padding="10")
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        # Host Entry
        ttk.Label(input_frame, text="Target IP / Hostname:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        self.target_entry.insert(0, "127.0.0.1")

        # Port Range
        ttk.Label(input_frame, text="Start Port:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.start_port = tk.IntVar(value=1)
        ttk.Spinbox(input_frame, from_=1, to=65535, textvariable=self.start_port, width=10).grid(row=1, column=1, sticky=tk.W, padx=5)

        ttk.Label(input_frame, text="End Port:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        self.end_port = tk.IntVar(value=1024)
        ttk.Spinbox(input_frame, from_=1, to=65535, textvariable=self.end_port, width=10).grid(row=1, column=3, sticky=tk.W, padx=5)

        # Buttons
        btn_frame = ttk.Frame(self.parent, padding="10")
        btn_frame.pack(fill=tk.X)

        self.scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = ttk.Button(btn_frame, text="Clear Logs", command=self.clear_logs)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        # Progress
        prog_frame = ttk.Frame(self.parent, padding="10")
        prog_frame.pack(fill=tk.X)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(prog_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X)
        self.status_lbl = ttk.Label(prog_frame, text="Ready")
        self.status_lbl.pack(pady=2)

        # Results
        res_frame = ttk.LabelFrame(self.parent, text="Scan Output", padding="10")
        res_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.console = scrolledtext.ScrolledText(res_frame, width=80, height=15, font=("Courier", 9))
        self.console.pack(fill=tk.BOTH, expand=True)
        
        # Tags for coloring
        self.console.tag_config("open", foreground="green")
        self.console.tag_config("closed", foreground="gray")
        self.console.tag_config("error", foreground="red")
        self.console.tag_config("info", foreground="blue")

    def log(self, msg, tag="info"):
        self.console.insert(tk.END, msg + "\n", tag)
        self.console.see(tk.END)

    def clear_logs(self):
        self.console.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.status_lbl.config(text="Ready")

    def stop_scan(self):
        self.scanning = False
        self.status_lbl.config(text="Stopping...")

    def start_scan(self):
        target = self.target_entry.get().strip()
        start = self.start_port.get()
        end = self.end_port.get()

        if not target:
            messagebox.showerror("Error", "Please enter a target IP or Hostname.")
            return
        if start > end:
            messagebox.showerror("Error", "Start port cannot be greater than end port.")
            return

        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.clear_logs()
        
        threading.Thread(target=self.run_scan_thread, args=(target, start, end), daemon=True).start()

    def run_scan_thread(self, target, start, end):
        try:
            # Resolve hostname if needed
            target_ip = socket.gethostbyname(target)
            self.log(f"Starting scan on {target} ({target_ip})", "info")
            self.log(f"Range: {start}-{end}", "info")
            self.log("-" * 40, "info")
        except socket.gaierror:
            self.log(f"Could not resolve hostname: {target}", "error")
            self.scanning = False
            self.reset_buttons()
            return

        ports = list(range(start, end + 1))
        total = len(ports)
        completed = 0
        
        # Using ThreadPoolExecutor for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(self.check_port, target_ip, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                if not self.scanning:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                port, is_open = future.result()
                completed += 1
                
                if is_open:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    self.log(f"[+] Port {port:<5} OPEN ({service})", "open")
                
                # Update UI
                progress = (completed / total) * 100
                self.progress_var.set(progress)
                self.status_lbl.config(text=f"Scanning... {completed}/{total}")

        self.log("-" * 40, "info")
        if self.scanning:
            self.log("Scan Complete.", "info")
            self.status_lbl.config(text="Scan Complete")
        else:
            self.log("Scan Stopped by user.", "error")
            self.status_lbl.config(text="Stopped")
            
        self.scanning = False
        self.reset_buttons()

    def check_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5) # 500ms timeout
            result = sock.connect_ex((ip, port))
            sock.close()
            return port, result == 0
        except:
            return port, False

    def reset_buttons(self):
        self.parent.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
        self.parent.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))


class IPGameTab:
    """
    Logic and UI for the Public vs Private IP Game.
    """
    def __init__(self, parent):
        self.parent = parent
        self.score = 0
        self.high_score = 0
        self.current_ip = None
        self.game_active = False
        self.timer_seconds = 3.0
        self.remaining_time = 3.0
        self.timer_id = None
        
        self.setup_ui()
        
    def setup_ui(self):
        # Center container
        container = ttk.Frame(self.parent, padding="40")
        container.pack(fill=tk.BOTH, expand=True)
        
        # Header
        title = ttk.Label(container, text="Public vs Private IP Game", font=("Arial", 16, "bold"))
        title.pack(pady=(0, 10))
        
        # Instructions
        instr = ttk.Label(container, text="Guess if the IP is Public or Private.\nYou have 3 seconds per question!", 
                          font=("Arial", 10), justify=tk.CENTER)
        instr.pack(pady=(0, 20))
        
        # Score Board
        score_frame = ttk.Frame(container)
        score_frame.pack(fill=tk.X, pady=10)
        
        self.score_label = ttk.Label(score_frame, text="Current Streak: 0", font=("Arial", 12, "bold"), foreground="blue")
        self.score_label.pack(side=tk.LEFT, padx=20)
        
        self.highscore_label = ttk.Label(score_frame, text="High Score: 0", font=("Arial", 12))
        self.highscore_label.pack(side=tk.RIGHT, padx=20)
        
        # The Question (IP Address)
        self.question_frame = ttk.LabelFrame(container, text="Current IP", padding="20")
        self.question_frame.pack(fill=tk.X, pady=20)
        
        self.ip_display = ttk.Label(self.question_frame, text="PRESS START", font=("Courier", 24, "bold"), justify=tk.CENTER)
        self.ip_display.pack()
        
        # Timer Bar
        self.timer_var = tk.DoubleVar(value=100)
        self.timer_bar = ttk.Progressbar(container, variable=self.timer_var, maximum=100, length=300, orient=tk.HORIZONTAL)
        self.timer_bar.pack(fill=tk.X, pady=(0, 20))
        
        # Answer Buttons
        btn_frame = ttk.Frame(container)
        btn_frame.pack(pady=10)
        
        self.btn_private = ttk.Button(btn_frame, text="PRIVATE", command=lambda: self.check_answer("Private"), width=15)
        self.btn_private.pack(side=tk.LEFT, padx=10)
        
        self.btn_public = ttk.Button(btn_frame, text="PUBLIC", command=lambda: self.check_answer("Public"), width=15)
        self.btn_public.pack(side=tk.LEFT, padx=10)
        
        # Control Buttons
        self.btn_start = ttk.Button(container, text="Start Game", command=self.start_game, width=20)
        self.btn_start.pack(pady=20)
        
        # Feedback label
        self.feedback_label = ttk.Label(container, text="", font=("Arial", 11, "bold"))
        self.feedback_label.pack(pady=5)

        self.set_game_state(False)

    def set_game_state(self, active):
        self.game_active = active
        state = tk.NORMAL if active else tk.DISABLED
        self.btn_private.config(state=state)
        self.btn_public.config(state=state)
        self.btn_start.config(state=tk.DISABLED if active else tk.NORMAL)

    def generate_ip(self):
        # 50% chance for Private, 50% for Public to make game balanced
        if random.random() < 0.5:
            # Generate Private IP
            choice = random.choice(['10', '172', '192'])
            if choice == '10':
                return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            elif choice == '172':
                return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(0,255)}"
            else:
                return f"192.168.{random.randint(0,255)}.{random.randint(0,255)}"
        else:
            # Generate Public IP (ensure it's not private)
            while True:
                ip_int = random.randint(1, 0xFFFFFFFF)
                ip_obj = ipaddress.IPv4Address(ip_int)
                if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local and not ip_obj.is_multicast:
                    return str(ip_obj)

    def start_game(self):
        self.score = 0
        self.score_label.config(text=f"Current Streak: {self.score}")
        self.feedback_label.config(text="")
        self.set_game_state(True)
        self.next_round()

    def next_round(self):
        if not self.game_active: return
        
        self.current_ip = self.generate_ip()
        self.ip_display.config(text=self.current_ip, foreground="black")
        
        # Reset Timer
        self.remaining_time = self.timer_seconds
        self.timer_var.set(100)
        self.run_timer()

    def run_timer(self):
        if not self.game_active: return
        
        step_ms = 50
        decrement = (step_ms / 1000.0)
        self.remaining_time -= decrement
        
        pct = (self.remaining_time / self.timer_seconds) * 100
        self.timer_var.set(pct)
        
        if self.remaining_time <= 0:
            self.game_over("Time's Up!")
        else:
            self.timer_id = self.parent.after(step_ms, self.run_timer)

    def check_answer(self, user_guess):
        # Cancel timer
        if self.timer_id:
            self.parent.after_cancel(self.timer_id)
            self.timer_id = None
            
        is_private = ipaddress.IPv4Address(self.current_ip).is_private
        correct_answer = "Private" if is_private else "Public"
        
        if user_guess == correct_answer:
            self.score += 1
            self.score_label.config(text=f"Current Streak: {self.score}")
            self.feedback_label.config(text="Correct!", foreground="green")
            # Speed up slightly every 5 points, maxing at 1.0s
            if self.score % 5 == 0 and self.timer_seconds > 1.0:
                self.timer_seconds -= 0.2
            self.parent.after(500, self.next_round)
        else:
            self.game_over(f"Wrong! {self.current_ip} is {correct_answer}")

    def game_over(self, reason):
        self.game_active = False
        self.set_game_state(False)
        if self.score > self.high_score:
            self.high_score = self.score
            self.highscore_label.config(text=f"High Score: {self.high_score}")
            reason += " (New High Score!)"
            
        self.ip_display.config(text="GAME OVER", foreground="red")
        self.feedback_label.config(text=reason, foreground="red")
        self.timer_seconds = 3.0 # Reset difficulty


class PasswordGeneratorTab:
    """
    Logic and UI for the Password Generator Tab.
    """
    def __init__(self, parent):
        self.parent = parent
        self.length_var = tk.IntVar(value=16)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.generated_password = tk.StringVar()
        
        self.setup_ui()

    def setup_ui(self):
        container = ttk.Frame(self.parent, padding="20")
        container.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(container, text="Secure Password Generator", 
                 font=('Arial', 16, 'bold')).pack(pady=(0, 20))

        # Options Frame
        opts_frame = ttk.LabelFrame(container, text="Options", padding="15")
        opts_frame.pack(fill=tk.X, pady=10)

        # Length
        len_frame = ttk.Frame(opts_frame)
        len_frame.pack(fill=tk.X, pady=5)
        ttk.Label(len_frame, text="Password Length:").pack(side=tk.LEFT)
        ttk.Spinbox(len_frame, from_=4, to=128, textvariable=self.length_var, width=5).pack(side=tk.LEFT, padx=10)
        
        # Checkboxes
        check_frame = ttk.Frame(opts_frame)
        check_frame.pack(fill=tk.X, pady=5)
        ttk.Checkbutton(check_frame, text="A-Z (Uppercase)", variable=self.use_upper).pack(anchor=tk.W)
        ttk.Checkbutton(check_frame, text="a-z (Lowercase)", variable=self.use_lower).pack(anchor=tk.W)
        ttk.Checkbutton(check_frame, text="0-9 (Digits)", variable=self.use_digits).pack(anchor=tk.W)
        ttk.Checkbutton(check_frame, text="!@# (Symbols)", variable=self.use_symbols).pack(anchor=tk.W)

        # Action Buttons
        btn_frame = ttk.Frame(container)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Generate Password", command=self.generate).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Copy to Clipboard", command=self.copy_clipboard).pack(side=tk.LEFT, padx=5)

        # Result Display
        res_frame = ttk.LabelFrame(container, text="Generated Password", padding="15")
        res_frame.pack(fill=tk.X, pady=10)
        
        self.entry_res = ttk.Entry(res_frame, textvariable=self.generated_password, font=('Courier', 12), state='readonly')
        self.entry_res.pack(fill=tk.X)

    def generate(self):
        chars = ""
        if self.use_upper.get(): chars += string.ascii_uppercase
        if self.use_lower.get(): chars += string.ascii_lowercase
        if self.use_digits.get(): chars += string.digits
        if self.use_symbols.get(): chars += string.punctuation

        if not chars:
            messagebox.showerror("Error", "Please select at least one character type.")
            return

        try:
            length = self.length_var.get()
            if length < 1: length = 1
            # Using secrets for cryptographic security
            pwd = ''.join(secrets.choice(chars) for _ in range(length))
            self.generated_password.set(pwd)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate: {e}")

    def copy_clipboard(self):
        pwd = self.generated_password.get()
        if pwd:
            self.parent.clipboard_clear()
            self.parent.clipboard_append(pwd)
            messagebox.showinfo("Success", "Password copied to clipboard!")


class NetworkToolSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Tool Suite V1.3")
        self.root.geometry("900x750")
        self.root.resizable(True, True)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Result.TLabel', font=('Arial', 10))
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 1: Subnet Calculator
        self.calc_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.calc_frame, text="  Subnet Calculator  ")
        self.calc_app = SubnetCalculatorTab(self.calc_frame)
        
        # Tab 2: Network Scanner
        self.scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_frame, text="  Network Ping Scanner  ")
        self.scanner_app = NetworkScannerTab(self.scanner_frame)
        
        # Tab 3: Port Scanner (NEW)
        self.port_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.port_frame, text="  Port Scanner  ")
        self.port_app = PortScannerTab(self.port_frame)
        
        # Tab 4: IP Game
        self.game_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.game_frame, text="  IP Game  ")
        self.game_app = IPGameTab(self.game_frame)
        
        # Tab 5: Password Generator
        self.pwd_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.pwd_frame, text="  Password Generator  ")
        self.pwd_app = PasswordGeneratorTab(self.pwd_frame)
        
        self.status_bar = ttk.Label(self.root, text="Network Tool Suite Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolSuite(root)
    root.mainloop()
