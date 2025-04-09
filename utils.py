import os
import socket
import fcntl
import struct

from scapy.utils import PcapWriter
from yaml import safe_load

def cleanup():
    logs_folder = os.listdir('logs/')

    if not logs_folder:
        return

    for log in logs_folder:
        try:
            if log.endswith('.pcap'):
                os.remove(f'logs/{log}')
        except FileNotFoundError:
            continue


def write_pcap_file(pcap_file, packet):
    """
    A kuldott/elfogott csomagok kiirasa a pcap fileba
    """
    file_path = f'logs/{pcap_file}.pcap'

    pcap_writer = PcapWriter(file_path, append= True, sync= True)
    pcap_writer.write(packet)


def get_config(filepath):
    with open(filepath, 'r') as file:
        config = safe_load(file)

    return config


def get_device_interfaces_w_mac():
    interfaces = {}

    interface_names = os.listdir('/sys/class/net/')
    for interface_name in interface_names:
        if interface_name == 'lo':
            continue

        mac = get_interface_mac(interface_name)
        ip = get_interface_ip(interface_name)
        interfaces[interface_name] = {'mac': mac, 'ip': ip}

    return interfaces


def get_interface_mac(name):
    mac = os.popen(f'cat /sys/class/net/{name}/address').read().strip()
    return mac


def get_interface_ip(name):
    ip_cmd = os.popen(f"ip addr show {name} | grep 'inet '").read()
    ip_address = ip_cmd.split()[1].strip('/8')
    return ip_address
