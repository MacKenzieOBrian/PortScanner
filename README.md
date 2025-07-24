# Enhanced Port Scanner

A professional-grade port scanning tool with advanced features for cybersecurity professionals and enthusiasts. This tool helps identify open ports, running services, and potential vulnerabilities on target systems.

## Features

- **Multiple Port Specification**: Scan single ports, multiple ports, or port ranges
- **Service Detection**: Identify services running on open ports
- **Banner Grabbing**: Retrieve service banners for version and configuration information
- **Threaded Scanning**: Fast and efficient scanning using multiple threads
- **Multiple Output Formats**: Save results in text, JSON, or CSV format
- **Security-Focused**: Includes safety checks and ethical warnings
- **Detailed Reporting**: Comprehensive scan summaries and results

## Usage

### Basic Scanning

Scan common ports (1-1024) on a target:
```bash
python enhanced_portscanner.py example.com
```

### Advanced Options

Scan specific ports:
```bash
python enhanced_portscanner.py -p 22,80,443,8080 example.com
```

Scan a range of ports with more threads:
```bash
python enhanced_portscanner.py -p 1-5000 -t 200 example.com
```

### Output Formats

Save results in JSON format:
```bash
python enhanced_portscanner.py -o json example.com > scan_results.json
```

Save results in CSV format:
```bash
python enhanced_portscanner.py -o csv example.com > scan_results.csv
```

###  Command-Line 

```
usage: enhanced_portscanner.py [-h] [-p PORTS] [-t THREADS] [-T TIMEOUT] [-o {text,json,csv}] target

## Cybersecurity Importance

Port scanning is a fundamental aspect of network security and ethical hacking. Understanding how port scanning works is crucial for both offensive and defensive security professionals:

### For Security Professionals
- **Vulnerability Assessment**: Identify potentially vulnerable services
- **Network Mapping**: Understand the attack surface of a network
- **Security Auditing**: Verify firewall rules and network security controls
- **Incident Response**: Detect unauthorized services or potential breaches

### Key Security Concepts Demonstrated
1. **Attack Surface Analysis**: The tool helps identify potential entry points that attackers might exploit.
2. **Service Identification**: Understanding what services are running is the first step in securing them.
3. **Defense Mechanisms**: The project includes features that demonstrate understanding of network security controls.

My implementation demonstrates the fundamental concept of banner grabbing, similar to Nmap's -sV --script=banner functionality. While Nmap uses an extensive database of service fingerprints and supports multiple protocols, my implementation shows the core concept by sending a simple HTTP HEAD request to gather basic service information. This approach is similar to how Nmap operates but is implemented from scratch to demonstrate understanding of the underlying network protocols

https://www.studytonight.com/network-programming-in-python/building-a-port-scanner
https://medium.com/h7w/building-a-simple-python-tool-for-network-reconnaissance-capturing-server-banners-4f0a300803f0
T.J. O’Connor’s – Violent Python, 1st ed., Syngress, Novber 2008.