
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

https://www.studytonight.com/network-programming-in-python/building-a-port-scanner
https://medium.com/h7w/building-a-simple-python-tool-for-network-reconnaissance-capturing-server-banners-4f0a300803f0
T.J. O’Connor’s – Violent Python, 1st ed., Syngress, Novber 2008.
