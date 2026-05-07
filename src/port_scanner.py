import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from src.models import HostResult, ServiceInfo

logger = logging.getLogger(__name__)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443, 8888, 27017
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Dev", 27017: "MongoDB"
}


def scan_tcp_port(ip: str, port: int, timeout: float = 1.0) -> ServiceInfo:
    """Attempts TCP connection to determine port state."""
    svc = ServiceInfo(port=port, protocol="TCP", state="closed",
                      service=SERVICE_NAMES.get(port, "unknown"))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                svc.state = "open"
                logger.debug(f"[TCP] {ip}:{port} OPEN")
            else:
                svc.state = "closed"
    except socket.timeout:
        svc.state = "filtered"
    except Exception as e:
        logger.debug(f"[TCP] {ip}:{port} error: {e}")
        svc.state = "error"
    return svc


def scan_host_ports(host: HostResult, ports: List[int] = None,
                    timeout: float = 1.0, max_workers: int = 100) -> HostResult:
    """Scans all specified ports on a single host using threads."""
    if ports is None:
        ports = COMMON_PORTS

    logger.info(f"Scanning {len(ports)} ports on {host.ip}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_tcp_port, host.ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            svc = future.result()
            host.ports.append(svc)

    host.ports.sort(key=lambda x: x.port)
    open_count = len([p for p in host.ports if p.state == "open"])
    logger.info(f"{host.ip}: {open_count} open port(s) found")
    return host
