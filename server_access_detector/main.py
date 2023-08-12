import ipaddress
import logging

from functools import partial

from server_access_detector.arp_standin import ArpStandinServer
from server_access_detector.smb_sniffer import SMB2Sniffer
from server_access_detector.wake_on_lan import send_wol_packet

__version__ = "0.1.0"


def main():
    # Configure logger
    logging.basicConfig(encoding="utf-8", level=logging.DEBUG)

    # server = ArpStandinServer("eth0", ipaddress.ip_address("6.6.6.16"), "00:13:37:00:00:16")
    # server.relay_arp_packages()

    targetIP = ipaddress.ip_address("127.0.0.1")
    targetMAC = "d0:50:99:0a:e6:21"
    networkInterface = "lo"

    sniffer = SMB2Sniffer(networkInterface, targetIP, targetMAC)
    sniffer.sniff_smb_packages(partial(send_wol_packet, networkInterface, targetMAC))


if __name__ == "__main__":
    main()
