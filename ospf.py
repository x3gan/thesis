import os
import sys
import threading
import time
from itertools import count

from duplicity.config import timeout
from scapy.sendrecv import sniff

import utils

class OSPF:
    def __init__(self, name, config_path):
        self.name = name

        ospf_config = utils.get_config(config_path)['ospf'][self.name]
        self.rid = ospf_config['rid']
        self.areaid = ospf_config['areaid']
        self.netmask = ospf_config['netmask']
        self.interfaces = utils.get_device_interfaces_w_mac()
        self.neighbours = {}
        self.neighbour_states = {intf : {'name' : None, 'state' : 'DOWN'} for
                                 intf in self.interfaces}

    def display_info(self):
        print(f'OSPF Name: {self.name}')
        print(f'OSPF RID: {self.rid}')
        print(f'OSPF Area ID: {self.areaid}')
        print(f'OSPF Netmask: {self.netmask}')
        print(f'OSPF Interfaces: {self.interfaces}')
        print(f'OSPF Neighbours: {self.neighbours}')
        print(f'OSPF Neighbour States: {self.neighbour_states}')

    def send_hello_packet(self, intf):
        pass

    @staticmethod #to remove
    def receiving_packets(intf):
        while True:
            packet = sniff(iface= intf, count= 1, timeout= 1)

            if not packet:
                continue
            else:
                pass


if __name__ == '__main__':
    filepath = 'ospf.yml'
    device_name = sys.argv[1]

    ospf = OSPF(device_name, filepath)
    ospf.display_info()

    for interface in ospf.interfaces.items():
        threading.Thread(target= ospf.receiving_packets, args= (interface[0],)).start()