import ipaddress
import logging

from time import sleep
from binascii import unhexlify

from scapy.config import conf as scapyConf
from scapy.sendrecv import sniff as scapy_sniff
from scapy.sendrecv import sendp as scapy_send_layer2_packet
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from server_access_detector.utils import list_available_interfaces

# Enable global libpcap integration
scapyConf.use_pcap = True


class SMB2Sniffer:
    def __init__(
        self,
        networkInterface: str,
        targetIP: ipaddress.IPv4Address | ipaddress.IPv6Address,
        targetMAC: str,
        magicPacketPort: int = 9,
    ) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.root.level)

        if networkInterface not in list_available_interfaces():
            raise ValueError(
                f"Can not use interface {networkInterface}.\nAvaliable interfaces are {list_available_interfaces()}"
            )

        self.networkInterface = networkInterface
        self.targetIP = targetIP
        self.targetMAC = targetMAC.replace("-", ":")  # Force uniform MAC format
        self.magicPacketPort = magicPacketPort

        self.broadcastMAC = "ff:ff:ff:ff:ff:ff"
        self.wolPayload = self.build_wol_payload()

        self.logger.info(f"Initialized with IP {self.targetIP.compressed} on {self.networkInterface}")

    def sniff_smb_packages(self) -> None:
        filter = f"tcp and dst port 445 and dst host {self.targetIP.compressed}"

        self.logger.info(f"Begin packet capturing with filter: {filter}")

        while True:
            try:
                packets = scapy_sniff(filter=filter, count=1, iface=self.networkInterface)
            except Exception as err:
                logging.error(err)
                return

            if len(packets) == 0:  # Canceled
                return

            if self.logger.level <= logging.INFO:
                packets.summary()

            packetSMB = packets[0]

            logging.info(f"Received SMB package for {self.targetIP.compressed} from {packetSMB.payload.psrc}")
            if self.logger.level <= logging.DEBUG:
                packetSMB.show()

            # Send WOL magic pakets
            self._send_wol_raw()
            if IP in packetSMB:
                self._send_wol_udp4()
            elif IPv6 in packetSMB:
                self._send_wol_udp6()

            sleep(600)
            
    def build_wol_payload(self):
        """ PAYLOAD: broadcast MAC + 16* target MAC as bytes
        
        """

        addr = b""
        for part in self.broadcastMAC.split(':'):
            addr += unhexlify(part);
        magic = b""
        for part in self.targetMAC.split(':'):
            magic += unhexlify(part);

        payload = addr + magic*16
        return payload
    
    def _send_wol_raw(self) -> None:
        # Ethertype 0x0842 + WOL Payload
        scapy_send_layer2_packet([Ether(type=int('0842', 16), dst=self.broadcastMAC) / Raw(load=self.wolPayload)], iface=self.networkInterface)

    def _send_wol_udp4(self) -> None:
        # UDP port 9 + WOL Payload
        scapy_send_layer2_packet([Ether(dst=self.broadcastMAC) / IP(dst='255.255.255.255') / UDP(sport=32767, dport=9)/ Raw(load=self.wolPayload)], iface=self.networkInterface)

    def _send_wol_udp6(self) -> None:
        # UDP port 9 + WOL Payload
        scapy_send_layer2_packet([Ether() / IPv6(dst='ff02::1') / UDP(sport=32767, dport=9)/ Raw(load=self.wolPayload)], iface=self.networkInterface)
