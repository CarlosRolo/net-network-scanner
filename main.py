#!/usr/bin/env python3
"""
NET-03: Network Scanner
Author: Carlos Rodriguez — github.com/CarlosRolo
"""
import argparse
import logging
import sys
from datetime import datetime

from src.banner_grabber import enrich_host_banners
from src.host_discovery import discover_hosts
from src.models import ScanResult
from src.port_scanner import COMMON_PORTS, scan_host_ports
from src.report_gen import generate_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="NET-03 Network Scanner — Nmap-like tool in Python",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", help="Target IP or CIDR (e.g. 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("--method", choices=["icmp", "arp"], default="icmp",
                        help="Host discovery method (default: icmp)")
    parser.add_argument("--ports", default="common",
                        help="Ports to scan: 'common', 'all', or comma-separated list (e.g. 22,80,443)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Timeout per probe in seconds (default: 1.0)")
    parser.add_argument("--workers", type=int, default=100,
                        help="Max threads for port scanning (default: 100)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Skip banner grabbing")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip HTML report generation")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug output")
    return parser.parse_args()


def resolve_ports(ports_arg: str):
    if ports_arg == "common":
        return COMMON_PORTS
    if ports_arg == "all":
        return list(range(1, 1025))
    try:
        return [int(p.strip()) for p in ports_arg.split(",")]
    except ValueError:
        logger.error("Invalid --ports value. Use 'common', 'all', or '22,80,443'")
        sys.exit(1)


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print(f"""
╔══════════════════════════════════════════╗
║       NET-03 Network Scanner             ║
║       github.com/CarlosRolo              ║
╚══════════════════════════════════════════╝
  Target  : {args.target}
  Method  : {args.method.upper()}
  Timeout : {args.timeout}s
  Workers : {args.workers}
""")

    result = ScanResult(target=args.target)
    ports = resolve_ports(args.ports)

    # Step 1: Host discovery
    print("[1/3] Discovering hosts...")
    hosts = discover_hosts(
        target=args.target,
        method=args.method,
        timeout=int(args.timeout),
        max_workers=args.workers,
    )

    if not hosts:
        print("[-] No alive hosts found. Exiting.")
        sys.exit(0)

    print(f"[+] Found {len(hosts)} alive host(s)\n")
    result.hosts = hosts

    # Step 2: Port scanning
    print(f"[2/3] Scanning {len(ports)} port(s) per host...")
    for host in result.hosts:
        scan_host_ports(host, ports=ports, timeout=args.timeout, max_workers=args.workers)
        open_ports = [p for p in host.ports if p.state == "open"]
        print(f"    {host.ip} — {len(open_ports)} open port(s)")

    # Step 3: Banner grabbing
    if not args.no_banner:
        print("\n[3/3] Grabbing banners...")
        for host in result.hosts:
            enrich_host_banners(host, timeout=args.timeout + 1)

    result.end_time = datetime.now()
    duration = (result.end_time - result.start_time).total_seconds()

    # Summary
    print(f"""
╔══════════════════════════════════════════╗
║              Scan Complete               ║
╚══════════════════════════════════════════╝
  Alive hosts : {len(result.alive_hosts)}
  Open ports  : {result.total_open_ports}
  Duration    : {duration:.1f}s
""")

    # Report
    if not args.no_report:
        report_path = generate_report(result)
        print(f"[+] Open in browser: file://$(pwd)/{report_path}\n")


if __name__ == "__main__":
    main()
