import ipaddress
import logging

from scapy.config import conf as scapyConf
from scapy.sendrecv import sniff as scapy_sniff
from scapy.sendrecv import sendp as scapy_send_layer2_packet
from scapy.packet import Packet as ScapyPacket
from scapy.layers.l2 import Ether as ScapyEther, ARP as ScapyARP

# from scapy.layers.l2 import ARP_am as scapyARPAnsweringMachine

from server_access_detector.utils import get_mac_from_interface, list_available_interfaces

# Enable global libpcap integration
scapyConf.use_pcap = True


class ArpStandinServer:
    def __init__(
        self,
        networkInterface: str,
        targetIP: ipaddress.IPv4Address | ipaddress.IPv6Address,
        targetMAC: str,
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

        self.logger.info(
            f"Initialized with traget IP {self.targetIP.compressed} and target MAC {self.targetMAC} on {self.networkInterface}"
        )

    def create_arp_reply(self, packet: ScapyPacket) -> ScapyPacket:
        packetARPResponse = ScapyEther(src=self.targetMAC, dst=packet.hwsrc) / ScapyARP(
            op=2, hwsrc=self.targetMAC, psrc=packet.pdst, hwdst=packet.hwsrc, pdst=packet.psrc
        )
        return packetARPResponse

    def relay_arp_packages(self) -> None:
        filter = f"arp and arp[6:2] == 1 and arp[24:4] == 0x{self.targetIP:X}"

        self.logger.info(f"Begin packet capturing with filter: {filter}")

        while True:
            try:
                packets = scapy_sniff(filter=filter, count=1, iface=self.networkInterface)
            except Exception as err:
                logging.error(err)
                return

            if len(packets) == 0:  # Canceled
                return

            packetARPReqest = packets[0]

            logging.info(f"Received ARP request for {self.targetIP} from {packetARPReqest.psrc}")
            if self.logger.level <= logging.DEBUG:
                packetARPReqest.show()

            packetARPResponse = self.create_arp_reply(packetARPReqest)
            scapy_send_layer2_packet(packetARPResponse, iface=self.networkInterface, verbose=0)

            logging.info(f"Sent ARP response from {packetARPResponse.psrc} to {packetARPResponse.pdst}")
            if self.logger.level <= logging.DEBUG:
                packetARPResponse.show()

    # def relay_arp_packages(self) -> None:
    #     relay = scapyARPAnsweringMachine(IP_addr=self.targetIP.compressed, ARP_addr=self.targetMAC)
    #     relay.run()
