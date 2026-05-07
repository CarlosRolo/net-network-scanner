import logging
import re
import socket
from typing import Optional

from src.models import HostResult, ServiceInfo

logger = logging.getLogger(__name__)

HTTP_PROBES = {
    80: b"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n",
    8443: b"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n",
    8888: b"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n",
    443: b"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n",
}

VERSION_PATTERNS = [
    (r"SSH-[\d.]+-(.+)", "SSH"),
    (r"220[ -](.+?)\r?\n", "FTP/SMTP"),
    (r"Server:\s*(.+?)\r?\n", "HTTP Server"),
    (r"OpenSSH_([\d.]+\w*)", "OpenSSH"),
    (r"Apache/([\d.]+)", "Apache"),
    (r"nginx/([\d.]+)", "nginx"),
    (r"MySQL.*?([\d.]+)", "MySQL"),
    (r"Microsoft.*?IIS/([\d.]+)", "IIS"),
]


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Connects to a port and reads the banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # Send HTTP probe if applicable
            if port in HTTP_PROBES:
                probe = HTTP_PROBES[port].replace(b"{ip}", ip.encode())
                s.sendall(probe)

            raw = s.recv(1024)
            banner = raw.decode("utf-8", errors="ignore").strip()
            return banner[:300] if banner else None

    except (socket.timeout, ConnectionRefusedError):
        return None
    except Exception as e:
        logger.debug(f"[Banner] {ip}:{port} error: {e}")
        return None


def detect_version(banner: str) -> str:
    """Extracts version info from a banner string."""
    for pattern, _ in VERSION_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:80]
    return ""


def enrich_host_banners(host: HostResult, timeout: float = 2.0) -> HostResult:
    """Grabs banners for all open ports on a host."""
    open_ports = [p for p in host.ports if p.state == "open"]
    logger.info(f"Grabbing banners for {len(open_ports)} open port(s) on {host.ip}")

    for svc in open_ports:
        banner = grab_banner(host.ip, svc.port, timeout=timeout)
        if banner:
            svc.banner = banner
            svc.version = detect_version(banner)
            logger.debug(f"[Banner] {host.ip}:{svc.port} -> {svc.version or 'no version'}")

    return host
