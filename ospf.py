import logging
import random
import sys
import threading
from time import sleep
from datetime import datetime

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

logging.basicConfig(level=logging.INFO)

class OSPF:
    def __init__(self, name, config_path):
        self.name = name

        ospf_config           = utils.get_config(config_path)['ospf'][self.name]
        self.interfaces       = utils.get_device_interfaces_w_mac()
        self.prio             = random.randint(1, 255)
        self.rid              = ospf_config['rid']
        self.areaid           = ospf_config['areaid']
        self.netmask          = ospf_config['netmask']
        """
        self.neighbour_states = {
            'eth0': {
                '10.0.0.2': {'last_seen': datetime.now(), 'state': 'TWOWAY'},
                '10.0.0.3': {'last_seen': datetime.now(), 'state': 'INIT'}
            },
            'eth1': {
                '10.0.0.4': {'last_seen': datetime.now(), 'state': 'TWOWAY'}
            }
        }...
        """
        self.neighbour_states = {
            intf: {} for intf in self.interfaces
        }

    def display_info(self):
        print(f'OSPF Name: {self.name}')
        print(f'OSPF RID: {self.rid}')
        print(f'OSPF Area ID: {self.areaid}')
        print(f'OSPF Netmask: {self.netmask}')
        print(f'OSPF Interfaces: {self.interfaces}')
        print(f'OSPF Neighbour States: {self.neighbour_states}')

    def send_hello_packet(self, intf):
        """
        :param intf:
        :return:
        """
        while True:
            neighbours = [
                neighbour for neighbour, state in self.neighbour_states[intf].items()
                if state['state'] != States.DOWN
            ]

            print(f'Az {self.interfaces[intf]["ip"]} interfészen az ismert szomszédok'
                  f' {neighbours}')

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
                        neighbors= neighbours
                    )
            )
            sendp(hello_packet, iface= intf, verbose= False)
            logging.info(f'[{datetime.now()}] Az {self.rid} - {intf} Hello csomagot küldött')
            sleep(HELLO_INTERVAL)

    def check_on_neighbours(self, intf):
        while True:
            # Alszik 5 másodpercet, hogy ne legyen túl gyakori a "lekérdezés"
            sleep(5)
            print('Szomszéd megfigyelése...')

            # Lista-másolat, különben hibát dob, iterálás közben nem lehetne módosítani
            for neighbour in list(self.neighbour_states[intf]):
                last_seen = self.neighbour_states[intf][neighbour]['last_seen']

                if not last_seen:
                    continue

                if (datetime.now() - last_seen).total_seconds() > DEAD_INTERVAL:

                    logging.info(f'[{datetime.now()}] {neighbour} szomszéd nem válaszol.')
                    self.neighbour_states[intf][neighbour] = {'last_seen': None, 'state':
                        States.DOWN}

    def receiving_packets(self, intf):
        print(f'Receiving packets on {intf}')
        while True:
            packet = sniff(iface= intf, count= 1, timeout= 1)

            if not packet:
                continue
            else:
                if packet[0].haslayer(OSPF_Hdr):
                    ospf_hdr = packet[0][OSPF_Hdr]
                    if ospf_hdr.type == 1 and ospf_hdr.src != self.rid:
                        neighbour = ospf_hdr.src

                        if neighbour not in self.neighbour_states[intf]:
                            self.neighbour_states[intf][neighbour] = {
                                'last_seen': datetime.now(),
                                'state'    : States.INIT
                            }
                            logging.info(f'[{datetime.now()}] Új szomszéd került a listába: {neighbour}')

                        if (
                            self.rid in packet[0][OSPF_Hello].neighbors and
                            neighbour in self.neighbour_states[intf]
                        ):
                            print(f'Listában lévő {neighbour} szomszéd már hallott rólam.')
                            self.neighbour_states[intf][neighbour]['state'] = States.TWOWAY

                            logging.info(f'[{datetime.now()}] {neighbour} : {States.INIT} ->'
                                         f' {States.TWOWAY}')
                        elif (
                            self.rid in packet[0][OSPF_Hello].neighbors and
                            neighbour not in self.neighbour_states[intf]
                        ):
                            logging.warning(f'{neighbour} már hallott rólam, de ő nincs a '
                                            f'listámban')

                            self.neighbour_states[intf][neighbour] = {
                                'last_seen': datetime.now(),
                                'state'    : States.TWOWAY
                            }

                        self.neighbour_states[intf][neighbour]['last_seen'] = datetime.now()
                else:
                    print('No OSPF Header found')

if __name__ == '__main__':
    filepath = 'ospf.yml'
    device_name = sys.argv[1]

    ospf = OSPF(device_name, filepath)
    ospf.display_info()

    threads = []

    for interface in ospf.interfaces:
        t1 = threading.Thread(target=ospf.receiving_packets, args=(interface,))
        t2 = threading.Thread(target=ospf.send_hello_packet, args=(interface,))
        t3 = threading.Thread(target=ospf.check_on_neighbours, args=(interface,))

        threads.extend([t1, t2, t3])

    for t in threads:
        t.start()