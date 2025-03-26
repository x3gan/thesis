import sys
import os

from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp

MULTICAST_IP = '224.0.0.5'
MULTICAST_MAC = '01:00:5e:00:00:05'

class OSPF:
    def __init__(self):
        self.a = sys.argv[1]
        self.mac_addresses = {}

    def get_interfaces(self):
        interfaces = os.listdir('/sys/class/net/')

        for interface in interfaces:
            print(interface)


        for interface in interfaces:
            with open(f'/sys/class/net/{interface}/address') as f:
                mac_address = f.read().strip()
            if interface != 'lo':
                self.mac_addresses[interface] = mac_address

        print(self.mac_addresses)

    def send_packet(self):
        hello = Ether(
            dst = MULTICAST_MAC,
            src = self.mac_addresses['R1-eth0']
        )
        sendp(hello, iface='R1-eth0', verbose=True)
        hello.show()

if __name__ == '__main__':
    ospf = OSPF()
    print(ospf.a)
    ospf.get_interfaces()
    ospf.send_packet()