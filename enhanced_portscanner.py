#!/usr/bin/env python3

import socket
import sys
import json
import csv
import time
import random
import argparse
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple
import ipaddress

# Custom Exceptions
class PortScannerError(Exception):
    pass

class ScanNotAllowedError(PortScannerError):
    pass

# Enums
class ScanType(Enum):
    """Types of port scans."""
    TCP_CONNECT = auto()
    TCP_SYN = auto()
    UDP = auto()
    FIN = auto()
    XMAS = auto()
    NULL = auto()

class PortStatus(Enum):
    """port statuses."""
    OPEN = "Open"
    CLOSED = "Closed"
    FILTERED = "Filtered"
    OPEN_FILTERED = "Open|Filtered"

# Data Classes
@dataclass
class ScanResult:
    """result of a port scan."""
    host: str
    port: int
    status: PortStatus
    service: str = "unknown"
    banner: str = ""
    scan_type: str = ""
    timestamp: str = ""

class PortScanner:
    # Common ports
    COMMON_PORTS = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        115: "SFTP", 135: "MS RPC", 139: "NetBIOS", 143: "IMAP",
        194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 514: "Syslog", 587: "SMTP", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    
    def __init__(self, target: str, ports: str = "1-1024", 
                 scan_type: ScanType = ScanType.TCP_CONNECT, 
                 threads: int = 100, timeout: float = 1.0,
                 output_format: str = "text"):

        self.target = target
        self.ports = self._parse_ports(ports)
        self.scan_type = scan_type
        self.threads = min(threads, 500)  # Limit threads to prevent resource exhaustion
        self.timeout = timeout
        self.output_format = output_format
        self.results: List[ScanResult] = []
        self.lock = Lock()
        self.queue = Queue()
        self.running = False
        
        # Validate target
        try:
            self.target_ip = self._resolve_target(target)
        except socket.gaierror:
            raise PortScannerError(f"Could not resolve hostname: {target}")
        
        # Security check 
        if self._is_private_ip(self.target_ip) and not self._confirm_private_scan():
            raise ScanNotAllowedError("Scanning private IPs requires explicit permission, I cant risk making this project illegal")
        
        # Log the start 
        self.start_time = datetime.now()
        print(f"[+] Starting {self.scan_type.name} scan for {self.target} ({self.target_ip})")
        print(f"[+] Scanning {len(self.ports)} ports from {min(self.ports)} to {max(self.ports)}")
    
    def _parse_ports(self, port_str: str) -> List[int]:
        ports = set()
        
        for part in port_str.split(','):
            part = part.strip()
            if not part:
                continue
                
            if '-' in part:
                # Handle port if range
                try:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end + 1))
                except (ValueError, IndexError):
                    raise PortScannerError(f"Invalid port range: {part}")
            else:
                # Handle single port
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                    else:
                        print(f"[!] Port {port} is out of range (1-65535), skipping")
                except ValueError:
                    raise PortScannerError(f"Invalid port: {part}")
        
        return sorted(ports)
    
    def _resolve_target(self, target: str) -> str:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise PortScannerError(f"Could not resolve hostname: {target}")
    
    def _is_private_ip(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    def _confirm_private_scan(self) -> bool:
        """You would have to ask for confirmation before scanning private IPs."""
        print("\n[!] WARNING: This is a private IP address range by the way!.")
        print("[!]  I should tell you scanning networks you don't own or have explicit permission to scan is ILLEGAL.")
        response = input("\nDo you have permission to scan this network? (y/N): ").strip().lower()
        return response == 'y'
    
    def _worker(self):
        """Worker thread for scanning ports."""
        while self.running:
            try:
                port = self.queue.get(timeout=1)
                self._scan_port(port)
                self.queue.task_done()
            except Exception as e:
                with self.lock:
                    print(f"[!] Error in worker thread: {e}")
                continue
    
    def _scan_port(self, port: int):
        try:
            # Create a new socket for each scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try to connect to the port
            result = sock.connect_ex((self.target_ip, port))
            
            # Determine port status
            if result == 0:  # Port is open
                banner = self._grab_banner(sock)
                service = self._identify_service(port, banner)
                
                result = ScanResult(
                    host=self.target_ip,
                    port=port,
                    status=PortStatus.OPEN,
                    service=service,
                    banner=banner,
                    scan_type=self.scan_type.name,
                    timestamp=datetime.now().isoformat()
                )
                
                with self.lock:
                    self.results.append(result)
                    print(f"[+] Port {port}/tcp open  {service:15} {banner}")
            
            sock.close()
            
        except socket.timeout:
            pass  # Port is filtered or host is down
        except Exception as e:
            with self.lock:
                print(f"[!] Error scanning port {port}: {e}")
    
    def _grab_banner(self, sock: socket.socket) -> str:
        try:
            # Try to receive some data
            sock.settimeout(2.0)  # Shorter timeout for banner grabbing
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "No banner received"
        except Exception:
            return "No banner received"
    
    def _identify_service(self, port: int, banner: str) -> str:
        # First check common ports
        service = self.COMMON_PORTS.get(port, "unknown")
        
        # Try to identify service from banner
        if banner:
            banner_lower = banner.lower()
            if "http" in banner_lower or "apache" in banner_lower or "nginx" in banner_lower:
                return "HTTP"
            elif "smtp" in banner_lower:
                return "SMTP"
            elif "ftp" in banner_lower:
                return "FTP"
            elif "ssh" in banner_lower:
                return "SSH"
            
        return service
    
    def scan(self):
        """Start the port scan."""
        if not self.ports:
            print("[!] No valid ports to scan")
            return
        
        self.running = True
        threads = []
        
        # Start worker threads
        for _ in range(min(self.threads, len(self.ports))):
            t = Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Add ports to the queue
        for port in self.ports:
            self.queue.put(port)
        
        # Wait for all ports to be processed
        self.queue.join()
        self.running = False
        
        # Wait for all threads to finish
        for t in threads:
            t.join(timeout=1.0)
        
        # Print summary
        self._print_summary()
    
    def _print_summary(self):
        """Print a summary of the scan results."""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        print("\n" + "="*50)
        print(f"Scan Summary")
        print("="*50)
        print(f"Target:        {self.target} ({self.target_ip})")
        print(f"Scan Type:     {self.scan_type.name}")
        print(f"Scanned Ports: {len(self.ports)}")
        print(f"Open Ports:    {len(self.results)}")
        print(f"Start Time:    {self.start_time}")
        print(f"End Time:      {end_time}")
        print(f"Duration:      {duration}")
        print("="*50 + "\n")
        
        # Print open ports
        if self.results:
            print("Open Ports:")
            print("PORT     STATE  SERVICE")
            for result in sorted(self.results, key=lambda x: x.port):
                print(f"{result.port:<8}/tcp {result.status.value:<6} {result.service}")
        else:
            print("No open ports found.")
    
    def save_results(self, filename: str = None):
        """Save scan results to a file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"portscan_{self.target_ip}_{timestamp}"
        
        if self.output_format == "json":
            self._save_json(filename + ".json")
        elif self.output_format == "csv":
            self._save_csv(filename + ".csv")
        else:
            self._save_text(filename + ".txt")
    
    def _save_json(self, filename: str):
        """Save results in JSON format."""
        try:
            with open(filename, 'w') as f:
                data = [{
                    'host': r.host,
                    'port': r.port,
                    'status': r.status.value,
                    'service': r.service,
                    'banner': r.banner,
                    'scan_type': r.scan_type,
                    'timestamp': r.timestamp
                } for r in self.results]
                
                json.dump({
                    'target': self.target,
                    'target_ip': self.target_ip,
                    'scan_type': self.scan_type.name,
                    'start_time': self.start_time.isoformat(),
                    'end_time': datetime.now().isoformat(),
                    'open_ports': [r.port for r in self.results],
                    'results': data
                }, f, indent=2)
                
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving JSON results: {e}")
    
    def _save_csv(self, filename: str):
        """Save results in CSV format."""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Port', 'Status', 'Service', 'Banner'])
                
                for result in sorted(self.results, key=lambda x: x.port):
                    writer.writerow([
                        f"{result.port}/tcp",
                        result.status.value,
                        result.service,
                        result.banner.replace('\n', ' ').replace('\r', '')
                    ])
                
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving CSV results: {e}")
    
    def _save_text(self, filename: str):
        """Save results in human-readable text format."""
        try:
            with open(filename, 'w') as f:
                f.write(f"Port Scan Results\n")
                f.write(f"{'='*50}\n")
                f.write(f"Target:        {self.target} ({self.target_ip})\n")
                f.write(f"Scan Type:     {self.scan_type.name}\n")
                f.write(f"Start Time:    {self.start_time}\n")
                f.write(f"End Time:      {datetime.now()}\n")
                f.write(f"Scanned Ports: {len(self.ports)}\n")
                f.write(f"Open Ports:    {len(self.results)}\n")
                f.write(f"{'='*50}\n\n")
                
                if self.results:
                    f.write("OPEN PORTS:\n")
                    f.write("PORT     STATE  SERVICE\n")
                    for result in sorted(self.results, key=lambda x: x.port):
                        f.write(f"{result.port:<8}/tcp {result.status.value:<6} {result.service}\n")
                        if result.banner and result.banner != "No banner received":
                            f.write(f"  |_ Banner: {result.banner[:100]}{'...' if len(result.banner) > 100 else ''}\n")
                else:
                    f.write("No open ports found.\n")
                
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving text results: {e}")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Enhanced Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Basic scan: python portscanner.py example.com
  Specific ports: python portscanner.py -p 80,443,8080 example.com
  Port range: python portscanner.py -p 1-1024 example.com
  JSON output: python portscanner.py -o json example.com
  CSV output: python portscanner.py -o csv example.com"""
    )
    
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                      help="Ports to scan (e.g., 80,443 or 1-1024) (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                      help="Number of threads (default: 100)")
    parser.add_argument("-T", "--timeout", type=float, default=1.0,
                      help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", choices=["text", "json", "csv"], default="text",
                      help="Output format (default: text)")
    
    return parser.parse_args()

def main():
    """Main function."""
    print("\n" + "="*50)
    print("SUMMER PROJECT PORT SCANNER")
    print("="*50)
    
    
    try:
        args = parse_arguments()
        
        # Create and run the scanner
        scanner = PortScanner(
            target=args.target,
            ports=args.ports,
            threads=args.threads,
            timeout=args.timeout,
            output_format=args.output
        )
        
        scanner.scan()
        
        # Save results
        if scanner.results:
            save = input("\nDo you want to save the results? (y/N): ").strip().lower()
            if save == 'y':
                filename = input(f"Enter filename (without extension) [portscan_{scanner.target_ip}]: ").strip()
                scanner.save_results(filename if filename else None)
        
        print("\n[+] Scan completed!")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except PortScannerError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
