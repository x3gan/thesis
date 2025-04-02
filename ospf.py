import logging
import random
import sys
import threading
from time import sleep
from datetime import datetime

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_DBDesc
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp, AsyncSniffer

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
                '10.0.0.2': {'last_seen': datetime.now(), 'state': 'TWOWAY', 'is_master': None},
                '10.0.0.3': {'last_seen': datetime.now(), 'state': 'INIT', 'is_master': False}
            },
            'eth1': {
                '10.0.0.4': {'last_seen': datetime.now(), 'state': 'TWOWAY', 'is_master': True},
            }
        }...
        
        is_master: Az aktualis router Master-e a szomszeddal kapcsolatban
        """
        self.neighbour_states = {
            intf: {} for intf in self.interfaces
        }
        self.lsdb = {}
        self.neighbour_states_lock = threading.Lock()

    def display_info(self):
        print(f'OSPF Name: {self.name}')
        print(f'OSPF RID: {self.rid}')
        print(f'OSPF Area ID: {self.areaid}')
        print(f'OSPF Netmask: {self.netmask}')
        print(f'OSPF Interfaces: {self.interfaces}')
        print(f'OSPF Neighbour States: {self.neighbour_states}')

    def send_hello_packet(self, intf):
        """
        :param intf: Annak az interfesznek a neve, amelyik a packetet kuldi
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
                        dst = MULTICAST_MAC,
                        src = self.interfaces[intf]['mac']
                    )/
                    IP(
                        dst   = MULTICAST_IP,
                        src   = self.interfaces[intf]['ip'],
                        proto = 89
                    )/
                    OSPF_Hdr(
                        version = 2,
                        type    = 1,
                        src     = self.rid,
                        area    = self.areaid

                    )/
                    OSPF_Hello(
                        mask          = self.netmask,
                        prio          = self.prio,
                        hellointerval = HELLO_INTERVAL,
                        deadinterval  = DEAD_INTERVAL,
                        neighbors     = neighbours
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
                    self.neighbour_states[intf][neighbour] = {
                        'last_seen' : None,
                        'state'     : States.DOWN,
                        'is_master' : None,
                        'ip'        : None,
                        'mac'       : None,
                    }

    def receiving_packets(self, intf):
        while True:
            packet = sniff(iface= intf, count= 1, timeout= 1) # -> async sniff

            if not packet:
                continue
            else:
                if packet[0].haslayer(OSPF_Hdr):
                    ospf_hdr = packet[0][OSPF_Hdr]
                    neighbour = ospf_hdr.src

                    if ospf_hdr.type == 1 and neighbour != self.rid:

                        if neighbour not in self.neighbour_states[intf]:
                            self.neighbour_states[intf][neighbour] = {
                                'last_seen': datetime.now(),
                                'state'    : States.INIT,
                                'is_master': None,
                                'ip'       : packet[0][IP].src,
                                'mac'      : packet[0][Ether].src
                            }
                            logging.info(f'[{datetime.now()}] Új szomszéd került a listába: {neighbour}')

                        if (
                                self.rid in packet[0][OSPF_Hello].neighbors and
                                neighbour in self.neighbour_states[intf] and
                                self.neighbour_states[intf][neighbour]['state'] == States.INIT
                        ):
                            self.neighbour_states[intf][neighbour]['state'] = States.TWOWAY

                            logging.info(f'[{datetime.now()}] {neighbour} : {States.INIT} ->'
                                         f' {States.TWOWAY}')
                        elif (
                                self.rid in packet[0][OSPF_Hello].neighbors and
                                neighbour not in self.neighbour_states[intf] and
                                self.neighbour_states[intf][neighbour]['state'] == States.INIT
                        ):

                            self.neighbour_states[intf][neighbour] = {
                                'last_seen': datetime.now(),
                                'state'    : States.TWOWAY
                            }

                        self.neighbour_states[intf][neighbour]['last_seen'] = datetime.now()

                        if self.neighbour_states[intf][neighbour]['state'] == States.TWOWAY:
                            self.neighbour_states[intf][neighbour]['state'] = States.EXSTART

                            logging.info(f'[{datetime.now()}] {neighbour} : {States.TWOWAY} ->'
                                         f' {States.EXSTART}')

                            self.send_dbd_packet(intf, neighbour)

                        # Ha az eredeti csomagot nem kapta meg, addig kuldjuk amig meg nem kapja
                        if (self.neighbour_states[intf][neighbour]['is_master'] is None and
                            self.neighbour_states[intf][neighbour]['state'] == States.EXSTART):
                            self.send_dbd_packet(intf, neighbour)

                    elif ospf_hdr.type == 2 and neighbour != self.rid:
                        pass


    def send_dbd_packet(self, intf, neighbour):
        """
        Ures DBD csomag kuldese, hogy eldontse 2 router, hogy ki a Master es ki a Slave

        :param intf: Az interfesz, amelyik a packetet kuldi
        :param neighbour: Az a szomszed, akivel a kapcsolatot szeretnenk felallitani
        """
        default_layers = (
            Ether(
                dst = self.neighbour_states[intf][neighbour]['mac'],
                src = self.interfaces[intf]['mac']
            )/
            IP(
                dst   = self.neighbour_states[intf][neighbour]['ip'],
                src   = self.interfaces[intf]['ip'],
                proto = 89
            )/
            OSPF_Hdr(
                version = 2,
                type    = 2,
                src     = self.rid,
                area    = self.areaid
            ))

        if (
            self.neighbour_states[intf][neighbour]['is_master'] is None and
            self.neighbour_states[intf][neighbour]['state'] == States.EXSTART
        ):

            dbd_packet_layer = (
                OSPF_DBDesc(
                    ddseq = 1
                )
            )

            dbd_packet = default_layers / dbd_packet_layer
            sendp(dbd_packet, iface=intf, verbose=False)

            logging.info(f'[{datetime.now()}] {self.rid} - {intf} kezdeti ures DBD csomagot '
                         f'kuldott {neighbour} -nak')

        elif (
                self.neighbour_states[intf][neighbour]['is_master'] is not None and
                self.neighbour_states[intf][neighbour]['state'] == States.EXCHANGE
        ):
            headers = self.generate_router_lsa()

            dbd_packet_layer = OSPF_DBDesc(
                ddseq      = random.randint(2, 65535),
                lsaheaders = headers
            )

            dbd_packet = default_layers / dbd_packet_layer
            sendp(dbd_packet, iface=intf, verbose=False)

            logging.info(f'[{datetime.now()}] {self.rid} - {intf} DBD csomagot kuldott '
                         f'{neighbour}-nak')

    def generate_router_lsa(self):
        return self.lsdb

if __name__ == '__main__':
    filepath = 'ospf.yml'
    device_name = sys.argv[1]

    ospf = OSPF(device_name, filepath)
    ospf.display_info()

    threads = []

    for interface in ospf.interfaces:
        receiver             = threading.Thread(target=ospf.receiving_packets, args=(interface,))
        hello_packet_sending = threading.Thread(target=ospf.send_hello_packet, args=(interface,))
        checking_neighbour   = threading.Thread(target=ospf.check_on_neighbours, args=(interface,))

        threads.extend([receiver, hello_packet_sending, checking_neighbour])

    for thread in threads:
        thread.start()