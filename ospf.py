import logging
import queue
import random
import sys
import threading
from time import sleep
from datetime import datetime

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_DBDesc
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp, AsyncSniffer
from sympy.codegen.ast import continue_

import utils
from states import States
from lsdb import LSDB
from neighbour import Neighbour

MULTICAST_IP = '224.0.0.5'
MULTICAST_MAC = '01:00:5e:00:00:05'

HELLO_INTERVAL = 10
DEAD_INTERVAL = 40

HELLO_PRIORITY = 1
DEFAULT_PRIORITY = 5

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

        self.neighbour_states = {
            intf: [] for intf in self.interfaces
        }
        self.lsdb = LSDB()

        self.packet_queue          = queue.PriorityQueue()
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
        10 másodpercenként küldi a router Hello csomagját, hogy jelezze még életben van.

        :param intf: Annak az interfesznek a neve, amelyik a csomagot kuldi
        """
        while True:

            if self.neighbour_states[intf]:
                neighbours = [
                    neighbour.rid for neighbour in self.neighbour_states[intf]
                    if neighbour.state != States.DOWN
                ]
            else:
                neighbours = []

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

            # Lista-másolat, különben hibát dob, iterálás közben nem lehetne módosítani
            for neighbour in list(self.neighbour_states[intf]):
                last_seen = neighbour.last_seen

                if not last_seen:
                    continue

                if (datetime.now() - last_seen).total_seconds() > DEAD_INTERVAL:
                    logging.info(f'[{datetime.now()}] {self.rid} - {intf} : {neighbour.rid} '
                                 f'szomszéd nem válaszol.')

                    self.neighbour_states[intf].remove(neighbour)

    def process_hello_packet(self, intf, packet, neighbour_rid):
        existing_neighbour = next(
            (neighbour for neighbour in self.neighbour_states[intf] if
             neighbour.rid == neighbour_rid),
            None
        )

        if not existing_neighbour:
            new_neighbour = Neighbour().build(
                rid=neighbour_rid,
                ip=packet[IP].src,
                mac=packet[Ether].src,
                last_seen=datetime.now(),
                state=States.INIT
            )
            self.neighbour_states[intf].append(new_neighbour)
            logging.info(
                f'[{datetime.now()}] Új szomszéd került a listába: {new_neighbour.rid}')
        else:
            existing_neighbour.last_seen = datetime.now()

        if self.rid in packet[OSPF_Hello].neighbors:
            if existing_neighbour and existing_neighbour.state == States.INIT:
                existing_neighbour.state = States.TWOWAY
                logging.info(f'[{datetime.now()}] {existing_neighbour.rid} : INIT -> TWOWAY')


    def process_dbd_packet(self, intf, packet, neighbour_rid):
        """
        OSPF Database Description (DBD) csomagok feldolgozása.
        intf:
        packet:
        neighbour_rid:
        """
        logging.info(f'[{datetime.now()}] OSPF DBD csomag érkezett {neighbour_rid}-től.')
        if packet[OSPF_DBDesc].ddseq == 1:
            print('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')

    def receiving_packets(self, intf):
        while True:
            packet = sniff(iface= intf, count= 1, timeout= 1) # -> async sniff

            if not packet:
                continue
            else:
                if packet[0].haslayer(OSPF_Hdr):
                    ospf_hdr = packet[0][OSPF_Hdr]
                    neighbour_rid = ospf_hdr.src

                    if self.rid == neighbour_rid:
                        continue

                    self.sort_packet(
                        header_type= ospf_hdr.type,
                        intf= intf,
                        packet= packet,
                        neighbour_rid= neighbour_rid
                    )


    def sort_packet(self, header_type, intf, packet, neighbour_rid):
        if header_type == 1:
            self.packet_queue.put((HELLO_PRIORITY, (intf, packet[0], neighbour_rid)))
        if header_type == 2:
            self.packet_queue.put((DEFAULT_PRIORITY, (intf, packet[0], neighbour_rid)))

    def process_queued_packet(self):
        while True:
            try:
                _, (intf, packet, neighbour_rid) = self.packet_queue.get(timeout=1)
            except queue.Empty:
                continue

            header_type = packet[OSPF_Hdr].type

            if header_type == 1:
                self.process_hello_packet(intf, packet, neighbour_rid)
            elif header_type == 2:
                self.process_dbd_packet(intf, packet, neighbour_rid)

    def send_dbd_packet(self, intf, neighbour_rid):
        """
        Ures DBD csomag kuldese, hogy eldontse 2 router, hogy ki a Master es ki a Slave

        :param intf: Az interfesz, amelyik a packetet kuldi
        :param neighbour_rid: Az a szomszed, akivel a kapcsolatot szeretnenk felallitani
        """
        neighbour = next((nbh for nbh in self.neighbour_states[intf]
                         if nbh.rid == neighbour_rid), None)

        if not neighbour:
            return

        default_layers = (
            Ether(
                dst = neighbour.mac,
                src = self.interfaces[intf]['mac']
            )/
            IP(
                dst   = neighbour.ip,
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
            neighbour.is_master is None and
            neighbour.state == States.EXSTART
        ):

            dbd_packet_layer = (
                OSPF_DBDesc(
                    ddseq = 1
                )
            )

            dbd_packet = default_layers / dbd_packet_layer
            sendp(dbd_packet, iface=intf, verbose=False)

            logging.info(f'[{datetime.now()}] {self.rid} - {intf} kezdeti ures DBD csomagot '
                         f'kuldott {neighbour.rid} -nak')

        elif (
                neighbour.is_master is not None and
                neighbour.state == States.EXCHANGE
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

    def global_state_watcher(self, intf):
        while True:
            for neighbour in self.neighbour_states[intf]:
                if neighbour.state == States.TWOWAY:
                    neighbour.state = States.EXSTART

                    logging.info(f'[{datetime.now()}] {self.rid} - {intf} : {neighbour.rid} '
                                 f'TWOWAY -> EXSTART')
                    sleep(2)
                    self.send_dbd_packet(intf, neighbour.rid)
                elif neighbour.state == States.EXSTART:
                    pass
                elif neighbour.state == States.EXCHANGE:
                    pass


if __name__ == '__main__':
    filepath = 'ospf.yml'
    device_name = sys.argv[1]

    ospf = OSPF(device_name, filepath)
    ospf.display_info()

    threads = []

    for interface in ospf.interfaces:
        receiver             = threading.Thread(target=ospf.receiving_packets, args=(interface,))
        hello_packet_sending = threading.Thread(target=ospf.send_hello_packet, args=(interface,))
        process_packet       = threading.Thread(target=ospf.process_queued_packet, args=())
        checking_neighbour   = threading.Thread(target=ospf.check_on_neighbours, args=(interface,))
        state_watcher        = threading.Thread(target=ospf.global_state_watcher, args=(interface,))

        threads.extend([
            receiver,
            hello_packet_sending,
            process_packet,
            checking_neighbour,
            state_watcher
        ])

    for thread in threads:
        thread.start()