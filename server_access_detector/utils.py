import ipaddress
import logging

from scapy.config import conf as scapyConf


def list_available_interfaces() -> list[str]:
    return list(scapyConf.ifaces.keys())


def get_mac_from_interface(networkInterface: str) -> str:
    for interfaceName in scapyConf.ifaces.keys():
        if interfaceName == networkInterface:
            return scapyConf.ifaces[interfaceName].mac

    errorMsg = f"Couldn't get MAC for interface {networkInterface}"
    if networkInterface not in scapyConf.ifaces.keys():
        errorMsg += f"\nAvaliable interfaces are {list_available_interfaces()}"
    raise ValueError(errorMsg)


def get_ip_from_interface(networkInterface: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    for interfaceName in scapyConf.ifaces.keys():
        if interfaceName == networkInterface:
            return ipaddress.ip_address(scapyConf.ifaces[interfaceName].ip)

    errorMsg = f"Couldn't get IP for interface {networkInterface}"
    if networkInterface not in scapyConf.ifaces.keys():
        errorMsg += f"\nAvaliable interfaces are {list_available_interfaces()}"
    raise ValueError(errorMsg)


def get_mac_from_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    for interfaceName in scapyConf.ifaces.keys():
        if scapyConf.ifaces[interfaceName].ip == ip.compressed:
            return scapyConf.ifaces[interfaceName].mac

    errorMsg = f"Couldn't get MAC for IP {ip}"
    raise ValueError(errorMsg)
