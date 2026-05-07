import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, sr1, srp

from src.models import HostResult

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)


def icmp_ping(ip: str, timeout: int = 1) -> HostResult:
    """Sends ICMP Echo Request and returns HostResult."""
    host = HostResult(ip=ip)
    try:
        pkt = IP(dst=ip) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
            host.is_alive = True
            try:
                host.hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                host.hostname = ""
            logger.debug(f"[ICMP] {ip} is alive")
    except Exception as e:
        logger.debug(f"[ICMP] {ip} error: {e}")
    return host


def arp_scan(network: str, timeout: int = 2) -> List[HostResult]:
    """ARP scan for a network range. More reliable on LAN."""
    results = []
    try:
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(arp_req, timeout=timeout, verbose=0)
        for _, rcv in answered:
            ip = rcv[ARP].psrc
            mac = rcv[ARP].hwsrc
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                pass
            host = HostResult(ip=ip, mac=mac, hostname=hostname, is_alive=True)
            results.append(host)
            logger.debug(f"[ARP] {ip} ({mac}) is alive")
    except Exception as e:
        logger.error(f"[ARP] scan error: {e}")
    return results


def discover_hosts(target: str, method: str = "icmp",
                   timeout: int = 1, max_workers: int = 50) -> List[HostResult]:
    """
    Discover live hosts on a target (single IP or CIDR range).
    method: 'icmp' | 'arp'
    """
    import ipaddress

    if method == "arp":
        logger.info(f"Starting ARP scan on {target}")
        return arp_scan(target, timeout=timeout)

    # ICMP — expand CIDR or single IP
    try:
        network = ipaddress.ip_network(target, strict=False)
        ips = [str(ip) for ip in network.hosts()]
    except ValueError:
        ips = [target]

    logger.info(f"Starting ICMP scan on {len(ips)} host(s)")
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(icmp_ping, ip, timeout): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result.is_alive:
                results.append(result)

    logger.info(f"Found {len(results)} alive host(s)")
    return results
