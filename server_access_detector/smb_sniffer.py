import ipaddress
import logging

from time import sleep
from typing import Callable

from scapy.config import conf as scapyConf
from scapy.sendrecv import sniff as scapy_sniff
from scapy.layers.inet import IP
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
    ) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.root.level)

        if networkInterface not in list_available_interfaces():
            raise ValueError(
                f"Can not use interface {networkInterface}.\nAvailable interfaces are {list_available_interfaces()}"
            )

        self.networkInterface = networkInterface
        self.targetIP = targetIP
        self.targetMAC = targetMAC.replace("-", ":")  # Force uniform MAC format

        self.logger.info(f"Initialized with IP {self.targetIP.compressed} on {self.networkInterface}")

    def sniff_smb_packages(self, callbackFunc: Callable | None = None) -> None:
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

            logging.info(f"Received SMB package for {self.targetIP.compressed} from {packetSMB.payload.src}")
            if self.logger.level <= logging.DEBUG:
                packetSMB.show()

            # Fire callback
            if callbackFunc:
                try:
                    callbackFunc()
                except Exception as err:
                    logging.error(err)

            try:
                sleep(600)
            except KeyboardInterrupt:
                return
