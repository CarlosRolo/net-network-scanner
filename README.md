# NET-03: Network Scanner

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5-green?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2-lightgrey)

A Python-based network scanner inspired by Nmap. Discovers live hosts via ICMP/ARP, scans TCP ports using multithreading, grabs service banners for version detection, and generates an interactive dark-themed HTML report.

Built as part of my networking portfolio — [github.com/CarlosRolo](https://github.com/CarlosRolo)

---

## Features

- **Host Discovery** — ICMP ping sweep and ARP scan over single IPs or CIDR ranges
- **Port Scanner** — Multithreaded TCP scanning with configurable port lists
- **Banner Grabbing** — Service and version detection via raw socket probes
- **HTML Report** — Dark-themed interactive report with filterable host/port table
- **CLI Interface** — Full argparse CLI with timeout, worker, method and port controls

---

## Architecture

```
Target (IP / CIDR)
        │
        ▼
   main.py ── Orchestrator (argparse · logging · ThreadPoolExecutor)
        │
        ├── host_discovery.py  →  ICMP ping / ARP scan     (Scapy)
        ├── port_scanner.py    →  TCP port scan             (Sockets + Threading)
        ├── banner_grabber.py  →  Service version detect    (Sockets + Regex)
        └── report_gen.py      →  Interactive HTML report
                │
                ▼
        scan_YYYYMMDD_HHMMSS.html
```

---

## Project Structure

```
net-network-scanner/
├── src/
│   ├── models.py          # ScanResult, HostResult, ServiceInfo dataclasses
│   ├── host_discovery.py  # ICMP ping sweep and ARP scan
│   ├── port_scanner.py    # Multithreaded TCP port scanner
│   ├── banner_grabber.py  # Service banner grabbing and version detection
│   └── report_gen.py      # Interactive HTML report generator
├── reports/
│   └── output/            # Generated HTML reports
├── tests/
│   └── test_scanner.py
├── docs/
├── main.py                # CLI entry point
├── requirements.txt
├── Makefile
└── README.md
```

---

## Installation

```bash
git clone https://github.com/CarlosRolo/net-network-scanner.git
cd net-network-scanner
pip install -r requirements.txt
```

> **Note:** Host discovery (ICMP/ARP) requires root/sudo to send raw packets.

---

## Usage

```bash
# Scan a single host
sudo python3 main.py 192.168.1.1

# Scan a full subnet
sudo python3 main.py 192.168.1.0/24

# Use ARP instead of ICMP (faster and more reliable on LAN)
sudo python3 main.py 192.168.1.0/24 --method arp

# Scan custom ports
sudo python3 main.py 192.168.1.0/24 --ports 22,80,443,8080

# Scan all ports 1-1024
sudo python3 main.py 192.168.1.0/24 --ports all

# Skip banner grabbing for faster scan
sudo python3 main.py 192.168.1.0/24 --no-banner

# Verbose/debug output
sudo python3 main.py 192.168.1.0/24 -v
```

---

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `target` | required | IP address or CIDR range to scan |
| `--method` | `icmp` | Host discovery method: `icmp` or `arp` |
| `--ports` | `common` | Port list: `common`, `all`, or `22,80,443` |
| `--timeout` | `1.0` | Probe timeout in seconds |
| `--workers` | `100` | Max threads for port scanning |
| `--no-banner` | `false` | Skip banner grabbing phase |
| `--no-report` | `false` | Skip HTML report generation |
| `-v / --verbose` | `false` | Enable debug logging |

---

## Sample Output

```
╔══════════════════════════════════════════╗
║       NET-03 Network Scanner             ║
║       github.com/CarlosRolo              ║
╚══════════════════════════════════════════╝
  Target  : 192.168.18.0/24
  Method  : ICMP
  Timeout : 1.0s
  Workers : 100

[1/3] Discovering hosts...
[+] Found 11 alive host(s)

[2/3] Scanning 23 port(s) per host...
    192.168.18.1   — 1 open port(s)
    192.168.18.53  — 3 open port(s)
    192.168.18.110 — 3 open port(s)
    192.168.18.214 — 4 open port(s)

[3/3] Grabbing banners...
    192.168.18.214:22 → OpenSSH_for_Windows_9.5

╔══════════════════════════════════════════╗
║              Scan Complete               ║
╚══════════════════════════════════════════╝
  Alive hosts : 11
  Open ports  : 14
  Duration    : 26.5s

[+] Report saved: reports/output/scan_20260506_192138.html
```

---

## Real Scan Results

Tested on a live home network (`192.168.18.0/24`):

| Host | Open Ports | Detected Service |
|------|-----------|-----------------|
| 192.168.18.1 | 1 | HTTP (router admin panel) |
| 192.168.18.53 | 3 | HTTP · HTTPS · HTTPS-Alt (web device) |
| 192.168.18.110 | 3 | HTTP · HTTPS · HTTPS-Alt |
| 192.168.18.214 | 4 | SSH · RPC · NetBIOS · SMB (Windows PC) |

Banner grabbing successfully identified `OpenSSH_for_Windows_9.5` on port 22.

---

## Technologies

| Tool | Purpose |
|------|---------|
| [Scapy 2.5](https://scapy.net/) | Raw packet crafting for ICMP/ARP host discovery |
| Python Sockets | TCP connection probing and banner grabbing |
| ThreadPoolExecutor | Parallel port scanning for performance |
| Dataclasses | Structured and typed scan result modeling |
| argparse | CLI argument parsing |

---

## Requirements

```
scapy==2.5.0
jinja2==3.1.4
colorama==0.4.6
```

---

## Legal Notice

This tool is intended for use **only on networks you own or have explicit written permission to scan**. Unauthorized network scanning may violate local laws and regulations. The author is not responsible for misuse.

---

## Author

**Carlos David Rodriguez Lopez**
Telematic Engineer — ESPOCH
Manta, Manabí, Ecuador
Riobamba, Chimborazo, Ecuador
GitHub: [github.com/CarlosRolo](https://github.com/CarlosRolo)
LinkedIn: [linkedin.com/in/carlosdrodriguezl](https://linkedin.com/in/carlosdrodriguezl)

---

## License

MIT License — see [LICENSE](LICENSE)
