import logging

from binascii import unhexlify

from scapy.sendrecv import sendp as scapy_send_layer2_packet
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6


BROADCAST_MAC: str = "ff:ff:ff:ff:ff:ff"
MAGIC_PACKET_PORT: int = 9


def build_wol_payload(broadcastMAC: str, targetMAC: str) -> bytes:
    """PAYLOAD: broadcast MAC + 16* target MAC as bytes"""

    addr = b""
    for part in broadcastMAC.split(":"):
        addr += unhexlify(part)
    magic = b""
    for part in targetMAC.split(":"):
        magic += unhexlify(part)

    payload = addr + magic * 16
    logging.debug(f"Created WOL payload > {payload}")

    return payload


def send_wol_packet_raw(networkInterface: str, broadcastMAC: str, wolPayload: bytes) -> None:
    # Ether type 0x0842 + WOL Payload
    packet = Ether(type=int("0842", 16), dst=broadcastMAC) / Raw(load=wolPayload)
    logging.debug(f"Created RAW wake on LAN packet > {packet}")
    scapy_send_layer2_packet([packet], iface=networkInterface)


def send_wol_packet_udp4(networkInterface: str, broadcastMAC: str, destinationPort: int, wolPayload: bytes) -> None:
    # UDP port 9 + WOL Payload
    packet = (
        Ether(dst=broadcastMAC)
        / IP(dst="255.255.255.255")
        / UDP(sport=32767, dport=destinationPort)
        / Raw(load=wolPayload)
    )
    logging.debug(f"Created IPv4 UDP wake on LAN packet > {packet}")
    scapy_send_layer2_packet(
        [packet],
        iface=networkInterface,
    )


def send_wol_packet_udp6(networkInterface: str, destinationPort: int, wolPayload: bytes) -> None:
    # UDP port 9 + WOL Payload
    packet = Ether() / IPv6(dst="ff02::1") / UDP(sport=32767, dport=destinationPort) / Raw(load=wolPayload)
    logging.debug(f"Created IPv6 UDP wake on LAN packet > {packet}")
    scapy_send_layer2_packet(
        [packet],
        iface=networkInterface,
    )


def send_wol_packet(networkInterface: str, targetMAC: str) -> None:
    wolPayload = build_wol_payload(broadcastMAC=BROADCAST_MAC, targetMAC=targetMAC)
    send_wol_packet_raw(networkInterface=networkInterface, broadcastMAC=BROADCAST_MAC, wolPayload=wolPayload)
    send_wol_packet_udp4(
        networkInterface=networkInterface,
        broadcastMAC=BROADCAST_MAC,
        destinationPort=MAGIC_PACKET_PORT,
        wolPayload=wolPayload,
    )
    send_wol_packet_udp6(networkInterface=networkInterface, destinationPort=MAGIC_PACKET_PORT, wolPayload=wolPayload)

    logging.info(f"Send wake on LAN packet to MAC {targetMAC} via interface {networkInterface}")
