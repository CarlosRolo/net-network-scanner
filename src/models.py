from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass
class ServiceInfo:
    port: int
    protocol: str       # TCP / UDP
    state: str          # open / closed / filtered
    service: str = "unknown"
    banner: str = ""
    version: str = ""

@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    mac: str = ""
    is_alive: bool = False
    ports: List[ServiceInfo] = field(default_factory=list)
    scan_time: float = 0.0

@dataclass
class ScanResult:
    target: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    hosts: List[HostResult] = field(default_factory=list)

    @property
    def alive_hosts(self):
        return [h for h in self.hosts if h.is_alive]

    @property
    def total_open_ports(self):
        return sum(
            len([p for p in h.ports if p.state == "open"])
            for h in self.alive_hosts
        )
