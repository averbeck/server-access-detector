import ipaddress
import logging

from server_access_detector.arp_standin import ArpStandinServer
from server_access_detector.smb_sniffer import SMB2Sniffer

__version__ = "0.1.0"


def main():
    # Configure logger
    logging.basicConfig(encoding="utf-8", level=logging.DEBUG)

    # server = ArpStandinServer("eth0", ipaddress.ip_address("6.6.6.16"), "00:13:37:00:00:16")
    # server.relay_arp_packages()

    sniffer = SMB2Sniffer("enp4s0", ipaddress.ip_address("6.6.6.16"), "d0:50:99:0a:e6:21")
    sniffer.sniff_smb_packages()


if __name__ == "__main__":
    main()
