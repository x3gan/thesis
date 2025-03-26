import random
import sys
import threading
from time import sleep

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp

import utils
from states import States

MULTICAST_IP = '224.0.0.5'
MULTICAST_MAC = '01:00:5e:00:00:05'

HELLO_INTERVAL = 10
DEAD_INTERVAL = 40

class OSPF:
    def __init__(self, name, config_path):
        self.name = name

        ospf_config           = utils.get_config(config_path)['ospf'][self.name]
        self.interfaces       = utils.get_device_interfaces_w_mac()
        self.prio             = random.randint(1, 255)
        self.rid              = ospf_config['rid']
        self.areaid           = ospf_config['areaid']
        self.netmask          = ospf_config['netmask']
        self.neighbours       = []
        self.neighbour_states = {intf : {'rid' : None, 'state' : 'DOWN'} for
                                 intf in self.interfaces}

    def display_info(self):
        print(f'OSPF Name: {self.name}')
        print(f'OSPF RID: {self.rid}')
        print(f'OSPF Area ID: {self.areaid}')
        print(f'OSPF Netmask: {self.netmask}')
        print(f'OSPF Interfaces: {self.interfaces}')
        print(f'OSPF Neighbour States: {self.neighbour_states}')

    def send_hello_packet(self, intf):
        while True:
            print(f'On {self.interfaces[intf]["ip"]} known neighbours are: {self.neighbours}')
            hello_packet = (
                    Ether(
                        dst= MULTICAST_MAC,
                        src= self.interfaces[intf]['mac']
                    )/
                    IP(
                        dst= MULTICAST_IP,
                        src= self.interfaces[intf]['ip'],
                        proto= 89
                    )/
                    OSPF_Hdr(
                        version= 2,
                        type= 1,
                        src= self.rid,
                        area= self.areaid

                    )/
                    OSPF_Hello(
                        mask= self.netmask,
                        prio= self.prio,
                        hellointerval= HELLO_INTERVAL,
                        deadinterval= DEAD_INTERVAL,
                        neighbors= self.neighbours
                    )
            )
            sendp(hello_packet, iface= intf, verbose= False)
            sleep(10)

    def receiving_packets(self, intf):
        print(f'Receiving packets on {intf}')
        while True:
            packet = sniff(iface= intf, count= 1, timeout= 1)

            if not packet:
                continue
            else:
                if packet[0].haslayer(OSPF_Hdr):
                    if packet[0][OSPF_Hdr].type == 1 and packet[0][OSPF_Hdr].src != self.rid:
                        neighbour = packet[0][OSPF_Hdr].src
                        if self.rid in packet[0][OSPF_Hello].neighbors and neighbour in self.neighbours:
                            print(f'{neighbour} already heard from me.')
                            self.neighbour_states[intf]['rid'] = neighbour
                            self.neighbour_states[intf]['state'] = States.TWOWAY
                        else:
                            if neighbour not in self.neighbours:
                                self.neighbours.append(neighbour)
                                self.neighbour_states[intf]['rid']   = neighbour
                                self.neighbour_states[intf]['state'] = States.INIT
                                print(f'Neighbour {neighbour} added')
                            else:
                                print(f'{neighbour} already in neighbours')
                    print(f'Neighbour state: {self.neighbour_states[intf]}')
                else:
                    print('No OSPF Header found')


if __name__ == '__main__':
    filepath = 'ospf.yml'
    device_name = sys.argv[1]

    ospf = OSPF(device_name, filepath)
    ospf.display_info()

    for interface in ospf.interfaces.items():
        threading.Thread(target= ospf.receiving_packets, args= (interface[0],)).start()
        threading.Thread(target= ospf.send_hello_packet, args= (interface[0],)).start()