"""
PCAP loader module for NetForensics.
Extracts metadata from traffic.pcap files using Scapy without inferring network anomalies.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Union

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS

from .exceptions import InvalidPcapError, PcapNotFoundError


@dataclass
class PacketRecord:
    """Structured representation of extracted PCAP packet metadata."""
    packet_index: int
    timestamp: float
    src_ip: Union[str, None]
    dst_ip: Union[str, None]
    protocol: str
    src_port: Union[int, None]
    dst_port: Union[int, None]
    length: int
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary representation."""
        return {
            "packet_index": self.packet_index,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "length": self.length,
            "summary": self.summary,
        }


def load_pcap(file_path: Union[str, Path]) -> List[PacketRecord]:
    """
    Loads and extracts packet metadata from a PCAP file using Scapy.

    Args:
        file_path: Path to the traffic.pcap file.

    Returns:
        List of PacketRecord objects.

    Raises:
        PcapNotFoundError: If the file does not exist.
        InvalidPcapError: If the PCAP file is corrupted or unreadable by Scapy.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise PcapNotFoundError(f"PCAP file not found: {path}")

    try:
        packets = rdpcap(str(path))
    except Exception as exc:
        raise InvalidPcapError(f"Could not read PCAP file '{path}': {exc}") from exc

    records: List[PacketRecord] = []

    for idx, pkt in enumerate(packets):
        timestamp = float(getattr(pkt, "time", 0.0))
        length = len(pkt)
        summary = pkt.summary()

        src_ip: Union[str, None] = None
        dst_ip: Union[str, None] = None
        src_port: Union[int, None] = None
        dst_port: Union[int, None] = None
        protocol = "UNKNOWN"

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)

            if pkt.haslayer(TCP):
                protocol = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                protocol = "DNS" if pkt.haslayer(DNS) else "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = "IP"
        elif pkt.haslayer(ARP):
            protocol = "ARP"
            arp_layer = pkt[ARP]
            src_ip = str(arp_layer.psrc)
            dst_ip = str(arp_layer.pdst)
        else:
            last_layer = pkt.lastlayer()
            protocol = getattr(last_layer, "name", "NON_IP")

        records.append(
            PacketRecord(
                packet_index=idx,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                length=length,
                summary=summary,
            )
        )

    return records
