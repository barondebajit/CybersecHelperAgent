import socket
import threading
import time
import json
import random
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from google import genai
from google.genai import types
import os
import dotenv

class NetworkScanner:
    def __init__(self, target, ports=None, threads=50, timeout=1, silent_mode=False):
        self.target = target
        self.ports = ports or list(range(1, 1001))
        self.threads = threads if not silent_mode else min(threads, 10)
        self.timeout = timeout if not silent_mode else max(timeout, 3)
        self.silent_mode = silent_mode
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'host_info': {},
            'services': {},
            'scan_stats': {}
        }
        
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 587: 'SMTP', 465: 'SMTPS', 3389: 'RDP', 5432: 'PostgreSQL',
            3306: 'MySQL', 1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch'
        }

    def resolve_hostname(self):
        try:
            ip = socket.gethostbyname(self.target)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = self.target
            
            self.results['host_info'] = {
                'hostname': hostname,
                'ip_address': ip,
                'resolved': True
            }
            return ip
        except socket.gaierror:
            self.results['host_info'] = {
                'hostname': self.target,
                'ip_address': None,
                'resolved': False,
                'error': 'Failed to resolve hostname'
            }
            return None

    def scan_port(self, ip, port):
        if self.silent_mode:
            time.sleep(random.uniform(0.1, 0.5))
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = self.identify_service(ip, port)
                return {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'protocol': 'tcp'
                }
            else:
                return {
                    'port': port,
                    'status': 'closed',
                    'service': None,
                    'protocol': 'tcp'
                }
        except socket.timeout:
            return {
                'port': port,
                'status': 'filtered',
                'service': None,
                'protocol': 'tcp'
            }
        except Exception as e:
            return {
                'port': port,
                'status': 'error',
                'service': None,
                'protocol': 'tcp',
                'error': str(e)
            }

    def identify_service(self, ip, port):
        service_info = {
            'name': self.common_ports.get(port, 'unknown'),
            'banner': None,
            'version': None
        }
        
        if not self.silent_mode:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                
                if port in [80, 8080]:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                elif port == 22:
                    pass
                elif port == 21:
                    pass
                else:
                    sock.send(b"GET / HTTP/1.1\r\n\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    service_info['banner'] = banner[:200]
                    if 'Server:' in banner:
                        server_line = [line for line in banner.split('\n') if 'Server:' in line]
                        if server_line:
                            service_info['version'] = server_line[0].split('Server:')[1].strip()
                
                sock.close()
            except:
                pass
        
        return service_info

    def udp_scan_port(self, ip, port):
        if self.silent_mode:
            time.sleep(random.uniform(0.2, 0.8))
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout * 2)
            
            parts = self.target.split('.')
            if port == 53:
                payload = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            elif port == 161:
                payload = b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
            else:
                payload = b'UDP_PROBE'
            
            sock.sendto(payload, (ip, port))
            data, addr = sock.recvfrom(1024)
            sock.close()
            
            return {
                'port': port,
                'status': 'open',
                'service': {'name': self.common_ports.get(port, 'unknown'), 'banner': None},
                'protocol': 'udp'
            }
        except socket.timeout:
            return {
                'port': port,
                'status': 'open|filtered',
                'service': None,
                'protocol': 'udp'
            }
        except Exception:
            return {
                'port': port,
                'status': 'closed',
                'service': None,
                'protocol': 'udp'
            }

    def scan_tcp_ports(self, ip):
        open_ports = []
        closed_ports = []
        filtered_ports = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in self.ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                
                if result['status'] == 'open':
                    open_ports.append(result)
                    self.results['services'][result['port']] = result['service']
                elif result['status'] == 'closed':
                    closed_ports.append(result)
                elif result['status'] == 'filtered':
                    filtered_ports.append(result)
                
                if not self.silent_mode:
                    print(f"Port {result['port']}: {result['status']}")
        
        return open_ports, closed_ports, filtered_ports

    def scan_udp_ports(self, ip, udp_ports=None):
        if udp_ports is None:
            udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 1194]
        
        udp_results = []
        
        with ThreadPoolExecutor(max_workers=min(self.threads, 5)) as executor:
            future_to_port = {executor.submit(self.udp_scan_port, ip, port): port for port in udp_ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                udp_results.append(result)
                
                if not self.silent_mode:
                    print(f"UDP Port {result['port']}: {result['status']}")
        
        return udp_results

    def detect_os(self, ip, open_ports):
        os_info = {
            'os_family': 'unknown',
            'confidence': 0,
            'details': []
        }
        
        if not open_ports:
            return os_info
        
        port_nums = [p['port'] for p in open_ports]
        
        windows_indicators = [135, 139, 445, 3389]
        linux_indicators = [22, 25, 53, 80, 443]
        
        windows_score = sum(1 for port in windows_indicators if port in port_nums)
        linux_score = sum(1 for port in linux_indicators if port in port_nums)
        
        if windows_score > linux_score:
            os_info['os_family'] = 'Windows'
            os_info['confidence'] = min(windows_score * 25, 100)
        elif linux_score > 0:
            os_info['os_family'] = 'Linux/Unix'
            os_info['confidence'] = min(linux_score * 20, 100)
        
        return os_info

    def scan(self, include_udp=False, output_file=None):
        start_time = time.time()
        
        print(f"Starting scan of {self.target}")
        print(f"Silent mode: {self.silent_mode}")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print("-" * 50)
        
        ip = self.resolve_hostname()
        if not ip:
            print("Failed to resolve target")
            return self.results
        
        print(f"Scanning {len(self.ports)} TCP ports...")
        open_ports, closed_ports, filtered_ports = self.scan_tcp_ports(ip)
        
        self.results['open_ports'] = open_ports
        self.results['closed_ports'] = closed_ports
        self.results['filtered_ports'] = filtered_ports
        
        if include_udp:
            print("Scanning common UDP ports...")
            udp_results = self.scan_udp_ports(ip)
            self.results['udp_ports'] = udp_results
        
        self.results['host_info']['os_detection'] = self.detect_os(ip, open_ports)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        self.results['scan_stats'] = {
            'total_ports_scanned': len(self.ports),
            'open_ports_found': len(open_ports),
            'scan_duration_seconds': round(scan_duration, 2),
            'ports_per_second': round(len(self.ports) / scan_duration, 2),
            'silent_mode': self.silent_mode
        }
        
        print("\n" + "="*50)
        print("SCAN COMPLETE")
        print(f"Open ports: {len(open_ports)}")
        print(f"Scan duration: {scan_duration:.2f} seconds")
        
        if output_file:
            self.save_results(output_file)
        
        return self.results

    def save_results(self, filename):
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"Results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

def scan_target_ports(target, ports=None, threads=50, timeout=1, silent_mode=False, include_udp=False, output_file=None):
    scanner = NetworkScanner(target, ports, threads, timeout, silent_mode)
    return scanner.scan(include_udp, output_file)

def scan_single_port(target, port, timeout=1):
    scanner = NetworkScanner(target, [port], 1, timeout, True)
    ip = scanner.resolve_hostname()
    if ip:
        result = scanner.scan_port(ip, port)
        return result
    return {'error': 'Failed to resolve target'}

def scan_port_range(target, start_port, end_port, threads=50, timeout=1, silent_mode=False):
    ports = list(range(start_port, end_port + 1))
    scanner = NetworkScanner(target, ports, threads, timeout, silent_mode)
    return scanner.scan()

def scan_common_ports(target, silent_mode=False):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 587, 465, 3389, 5432, 3306, 1433, 6379, 27017, 8080, 8443, 9200]
    scanner = NetworkScanner(target, common_ports, 20, 1, silent_mode)
    return scanner.scan()

def resolve_target_hostname(target):
    scanner = NetworkScanner(target, [80], 1, 1, True)
    ip = scanner.resolve_hostname()
    return scanner.results['host_info']

def detect_target_os(target, port_range=None):
    ports = port_range or [22, 80, 135, 139, 443, 445, 3389]
    scanner = NetworkScanner(target, ports, 10, 1, True)
    ip = scanner.resolve_hostname()
    if ip:
        open_ports, _, _ = scanner.scan_tcp_ports(ip)
        return scanner.detect_os(ip, open_ports)
    return {'error': 'Failed to resolve target'}

scan_ports_function = types.FunctionDeclaration(
    name="scan_target_ports",
    description="Perform comprehensive port scan on a target host with customizable options",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "target": types.Schema(
                type=types.Type.STRING,
                description="Target hostname or IP address to scan"
            ),
            "ports": types.Schema(
                type=types.Type.ARRAY,
                items=types.Schema(type=types.Type.INTEGER),
                description="List of specific ports to scan (default: 1-1000)"
            ),
            "threads": types.Schema(
                type=types.Type.INTEGER,
                description="Number of concurrent threads for scanning (default: 50)"
            ),
            "timeout": types.Schema(
                type=types.Type.INTEGER,
                description="Connection timeout in seconds (default: 1)"
            ),
            "silent_mode": types.Schema(
                type=types.Type.BOOLEAN,
                description="Enable silent mode for stealthy scanning (default: False)"
            ),
            "include_udp": types.Schema(
                type=types.Type.BOOLEAN,
                description="Include UDP port scanning (default: False)"
            ),
            "output_file": types.Schema(
                type=types.Type.STRING,
                description="Optional file path to save scan results"
            )
        },
        required=["target"]
    )
)

scan_single_port_function = types.FunctionDeclaration(
    name="scan_single_port",
    description="Scan a single specific port on a target",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "target": types.Schema(
                type=types.Type.STRING,
                description="Target hostname or IP address"
            ),
            "port": types.Schema(
                type=types.Type.INTEGER,
                description="Port number to scan"
            ),
            "timeout": types.Schema(
                type=types.Type.INTEGER,
                description="Connection timeout in seconds (default: 1)"
            )
        },
        required=["target", "port"]
    )
)

scan_range_function = types.FunctionDeclaration(
    name="scan_port_range",
    description="Scan a range of ports on a target",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "target": types.Schema(
                type=types.Type.STRING,
                description="Target hostname or IP address"
            ),
            "start_port": types.Schema(
                type=types.Type.INTEGER,
                description="Starting port number"
            ),
            "end_port": types.Schema(
                type=types.Type.INTEGER,
                description="Ending port number"
            ),
            "threads": types.Schema(
                type=types.Type.INTEGER,
                description="Number of concurrent threads (default: 50)"
            ),
            "timeout": types.Schema(
                type=types.Type.INTEGER,
                description="Connection timeout in seconds (default: 1)"
            ),
            "silent_mode": types.Schema(
                type=types.Type.BOOLEAN,
                description="Enable silent mode (default: False)"
            )
        },
        required=["target", "start_port", "end_port"]
    )
)

scan_common_function = types.FunctionDeclaration(
    name="scan_common_ports",
    description="Scan only the most common ports (21, 22, 23, 25, 53, 80, 443, etc.)",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "target": types.Schema(
                type=types.Type.STRING,
                description="Target hostname or IP address"
            ),
            "silent_mode": types.Schema(
                type=types.Type.BOOLEAN,
                description="Enable silent mode (default: False)"
            )
        },
        required=["target"]
    )
)

resolve_hostname_function = types.FunctionDeclaration(
    name="resolve_target_hostname",
    description="Resolve hostname to IP address and perform reverse DNS lookup",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "target": types.Schema(
                type=types.Type.STRING,
                description="Target hostname or IP address to resolve"
            )
        },
        required=["target"]
    )
)

detect_os_function = types.FunctionDeclaration(
    name="detect_target_os",
    description="Attempt to detect target operating system based on open ports",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "target": types.Schema(
                type=types.Type.STRING,
                description="Target hostname or IP address"
            ),
            "port_range": types.Schema(
                type=types.Type.ARRAY,
                items=types.Schema(type=types.Type.INTEGER),
                description="Specific ports to check for OS detection (default: common OS-indicating ports)"
            )
        },
        required=["target"]
    )
)