from datetime import datetime as dt
from datetime import timedelta as td
import logging
import queue
import sys
import threading
from time import sleep

from lxml.html.defs import link_attrs
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_Router_LSA, OSPF_LSUpd, OSPF_LSA_Hdr, \
    OSPF_Link
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff
from sympy.solvers.diophantine.diophantine import length

import utils
from lsdb import LSDB
from neighbour import Neighbour
from states import States

MULTICAST_IP = '224.0.0.5'
MULTICAST_MAC = '01:00:5e:00:00:05'

TIMEOUT        = 10
DEAD_INTERVAL  = 40
HELLO_INTERVAL = 10

logging.basicConfig(level=logging.INFO)


class OSPF:
    def __init__(self, name, config_path):
        """
        OSPF router inicializálása.
        :param name: A router neve, ahogy a halozatban szerepel
        :param config_path: Az OSPF konfiguracio eleresi utja
        """
        self.name = name

        ospf_config = utils.get_config(config_path)['ospf'][self.name]

        self.rid        = ospf_config['rid']
        self.areaid     = ospf_config['areaid']
        self.interfaces = utils.get_device_interfaces_w_mac()

        self.lsdb             = LSDB()
        self.packet_queue     = queue.PriorityQueue()
        self.neighbour_states = {intf: [] for intf in self.interfaces}

        self.neighbour_states_lock = threading.Lock()
        self.lsa_sequence_number   = 0
        self.last_lsa_update       = dt.now()
        self.is_simulation_done    = False

    def send_hello(self, intf : str) -> None:
        """
        OSPF Hello csomag küldése multicast címen.
        :param intf: Az az interfész, amelyik küldi a csomagot
        :return:
        """
        while True:
            if self.neighbour_states[intf]:
                neighbour_list = [
                    neighbour.rid for neighbour in self.neighbour_states[intf]
                    if neighbour.state != States.DOWN
                ]
            else:
                neighbour_list = []

            hello_packet = (
                    Ether(
                        dst = MULTICAST_MAC,
                        src = self.interfaces[intf]['mac']
                    ) /
                    IP(
                        dst   = MULTICAST_IP,
                        src   = self.interfaces[intf]['ip'],
                        proto = 89
                    ) /
                    OSPF_Hdr(
                        version = 2,
                        type    = 1,
                        src     = self.rid,
                        area    = self.areaid

                    ) /
                    OSPF_Hello(
                        hellointerval = HELLO_INTERVAL,
                        deadinterval  = DEAD_INTERVAL,
                        neighbors     = neighbour_list
                    )
            )

            sendp(x= hello_packet, iface= intf, verbose= False)
            utils.write_pcap_file(pcap_file= f'{intf}', packet= hello_packet)

            logging.info(f'[{dt.now()}] {self.name} - {intf} HELLO')

            sleep(HELLO_INTERVAL)

    def process_hello(self, intf : str, packet : Packet) -> None:
        if packet[OSPF_Hdr].src == self.rid:
            return

        with self.neighbour_states_lock:
            neighbour_rid = packet[OSPF_Hdr].src
            neighbour_ip  = packet[IP].src
            neighbour_mac = packet[Ether].src

            neighbour = self.get_neighbour(intf, neighbour_rid)

            if neighbour is None:
                neighbour = self.create_neighbour(neighbour_rid, neighbour_ip, neighbour_mac)
                self.neighbour_states[intf].append(neighbour)

                logging.info(f'[{dt.now()}] {self.name} - {intf} SZOMSZÉD INIT: {neighbour.rid}')

            neighbour.last_seen = dt.now()

            if self.rid in packet[OSPF_Hello].neighbors and neighbour.state == States.INIT:
                neighbour.state = States.TWOWAY

                logging.info(f'[{dt.now()}] {self.name} - {intf} SZOMSZÉD TWO-WAY: {neighbour.rid}')

    def get_neighbour(self, intf : str, src : str) -> Neighbour | None:
        for neighbour in self.neighbour_states[intf]:
            if neighbour.rid == src:
                return neighbour

        return None

    @staticmethod
    def create_neighbour(rid : str, ip : str, mac : str) -> Neighbour:
        """
        Szomszéd létrehozása az OSPF Hello csomag alapján.
        :param rid: A szomszéd router ID-ja
        :param ip: A szomszéd IP címe
        :param mac: A szomszéd MAC címe
        :return:
        """
        neighbour = Neighbour()

        neighbour.build(
            rid       = rid,
            ip        = ip,
            mac       = mac,
            last_seen = dt.now(),
            state     = States.INIT
        )

        return neighbour

    def listen(self, intf : str) -> None:
        """
        Az adott interfész figyel, és ha kap egy csomagot, akkor azt belerakja a packet queue-ba.
        :param intf: Az az interfész, amelyik figyeli a csomagokat
        :return:
        """
        while True:
            packets = sniff(iface= intf, count= 1)

            if packets:
                packet = packets[0]

                if packet.haslayer(OSPF_Hdr):
                    self.packet_queue.put((intf, packet))
                    utils.write_pcap_file(f'{intf}', packet)

                    logging.info(f'[{dt.now()}] {self.name} - {intf} CSOMAG ÉRKEZETT')

    def process_packet(self) -> None:
        """
        A packet queue-bol sorra olvassuk ki a csomagokat és típustól függően tovább küldi
        feldolgozásra őket.
        :return:
        """
        while True:
            try:
                intf, packet = self.packet_queue.get(timeout=1)
            except queue.Empty:
                continue

            header_type = packet[OSPF_Hdr].type

            if header_type == 1:  # Hello csomag
                self.process_hello(intf, packet)
            if header_type == 4: # LSUpdate csomag
                print(packet.show())
                #self.process_lsu(packet)

    def state_watch(self, intf : str) -> None:
        """
        Interfeszenkent megnezzuk a szomszedok allapotat es frissitjuk azt.
        :param intf: Az aktualis router azon interfesze, amelyiket nezunk
        :return:
        """
        while True:
            self.check_timeout()

            with self.neighbour_states_lock:
                for neighbour in list(self.neighbour_states[intf]):
                    if neighbour.state == States.TWOWAY:
                        neighbour.state = States.EXSTART
                        #update display database

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR EX-START:'
                                     f' {neighbour.display()}')
                    if neighbour.state == States.EXSTART:
                        neighbour.state = States.EXCHANGE
                        #update display database

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR EXCHANGE:'
                                     f' {neighbour.display()}')

                    if neighbour.state == States.EXCHANGE:
                        neighbour.state = States.LOADING
                        #update display database

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR LOADING:'
                                     f' {neighbour.display()}')

                    if neighbour.state == States.LOADING:
                        neighbour.state = States.FULL
                        self.generate_router_lsa()
                        #self.flood_lsa()

                        #update display database

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR FULL:'
                                     f' {neighbour.display()}')

            sleep(1)

    def generate_router_lsa(self):
        """
        Legeneraljuk az aktualis router LSA-jet, minden interfeszen, minden szomszeddal es ezt
        beletesszuk a router LSDB-jebe.
        :return:
        """
        lsa_type = 1
        link_type = 1

        links = []
        for intf, neighbours in self.neighbour_states.items():
            for neighbour in neighbours:
                if neighbour.state == States.FULL:
                    link = OSPF_Link(
                        type   = link_type,
                        id     = neighbour.rid,
                        data   = self.interfaces[intf]['ip'],
                        metric = 1
                    )
                    links.append(link)

        lsa = (
                OSPF_LSA_Hdr(
                    id  = self.rid,
                    seq = self.lsa_sequence_number
                ) /
                OSPF_Router_LSA(
                    linkcount = len(links),
                    linklist  = links
                )
        )


        self.lsa_sequence_number += 1
        self.lsdb.add(lsa)
        self.flood_lsa()

    def flood_lsa(self, intf = None, exclude = None):
        if intf is None:
            for intf in self.interfaces:
                self.flood_lsa(intf)
            return

        lsa_list = self.lsdb.get_all()

        for neighbour in self.neighbour_states[intf]:
            if neighbour.state == States.FULL:

                lsu_packet = (
                        Ether(
                            dst = neighbour.mac,
                            src = self.interfaces[intf]['mac']
                        ) /
                        IP(
                            dst   = neighbour.ip,
                            src   = self.interfaces[intf]['ip'],
                            proto = 89
                        ) /
                        OSPF_Hdr(
                            version = 2,
                            type    = 4,
                            src     = self.rid,
                            area    = self.areaid
                        ) / OSPF_LSUpd(
                            lsalist = lsa_list
                        )
                )

                sendp(x = lsu_packet, iface= intf, verbose= False)
                utils.write_pcap_file(pcap_file= f'{intf}', packet= lsu_packet)

                logging.info(f'[{dt.now()}] {self.name} - {intf} LSUPDATE')

    def is_down(self, intf):
        while True:
            with self.neighbour_states_lock:
                for neighbour in list(self.neighbour_states[intf]):
                    if neighbour.state == States.DOWN:
                        self.neighbour_states[intf].remove(neighbour)

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR DOWN: {neighbour.display()}')

            sleep(DEAD_INTERVAL)

    def process_lsu(self, packet):
        lsa_list = packet[OSPF_LSUpd].lsalist

        for lsa in lsa_list:
            self.process_lsa(lsa)



    def process_lsa(self, lsa):
        sender_rid = lsa[OSPF_Router_LSA].adrouter
        sender = self.lsdb.get(sender_rid)

        if sender is None:
            self.lsdb.add(lsa)

        sender = self.lsdb.get(sender_rid)

        if sender.seq > self.lsdb.get(sender_rid).seq:
            self.lsdb.add(lsa)
            self.last_lsa_update = dt.now()

            logging.info(f'[{dt.now()}] {self.name} - LSDB UPDATED: {lsa.summary()}')

            #flood except to sender
            self.flood_lsa(exclude= sender)

    def check_timeout(self):
        if self.lsdb.get_all() and self.last_lsa_update + td(seconds=TIMEOUT) < dt.now():
            self.is_simulation_done = True


if __name__ == '__main__':
    path = 'config/ospf.yml'

    router_name = sys.argv[1]

    utils.cleanup()

    ospf = OSPF(router_name, path)

    threads = []
    for interface in ospf.interfaces:
        hello_thread       = threading.Thread(target=ospf.send_hello, args=(interface,))
        listening_thread   = threading.Thread(target=ospf.listen, args=(interface,))
        #is_down_thread     = threading.Thread(target=ospf.is_down, args=(interface,))
        state_watch_thread = threading.Thread(target=ospf.state_watch, args=(interface,))

        threads.extend([
            hello_thread,
            listening_thread,
            #is_down_thread,
            state_watch_thread
        ])

    process_thread = threading.Thread(target=ospf.process_packet)
    threads.append(process_thread)

    try:
        for thread in threads:
            thread.start()


        while not ospf.is_simulation_done:
            sleep(1)

        if ospf.is_simulation_done:
            #log into tmp/router_name DONE
            #ospf.stop()
            pass


    except KeyboardInterrupt:
        print("\nLeállítás kérés érkezett...")
    finally:
        print("Szálak leállítása...")
        print("Program vége.")