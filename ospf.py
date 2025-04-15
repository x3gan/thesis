import os
from abc import ABC, abstractmethod
from datetime import datetime as dt
from datetime import timedelta as td
import logging
import queue
import sys
import threading
from time import sleep
from typing import Any

from lxml.html.defs import link_attrs
from reportlab.graphics.renderPS import PSCanvas
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_Router_LSA, OSPF_LSUpd, OSPF_LSA_Hdr, \
    OSPF_Link
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff
from sympy.solvers.diophantine.diophantine import length
from yaml import safe_load

import utils
from interface import Interface
from lsdb import LSDB
from neighbour import Neighbour
from states import States

MULTICAST_IP = '224.0.0.5'
MULTICAST_MAC = '01:00:5e:00:00:05'

TIMEOUT        = 10
DEAD_INTERVAL  = 40
HELLO_INTERVAL = 10

logging.basicConfig(level=logging.INFO)

def setup_logger(name : str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    log_path = f'logs/{name}.log'
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))

    logger.addHandler(file_handler)
    return logger


def cleanup() -> None:
    pass


def get_config(filepath):
    with open(filepath, 'r') as file:
        config = safe_load(file)

    return config


def get_interface_names(interfaces : list) -> list:
    interface_names = []

    for interface in interfaces:
        interface_name = interface['name']
        interface_names.append(interface_name)

    return interface_names


def get_interface_mac(name):
    mac = os.popen(f"cat /sys/class/net/{name}/address").read().strip()
    return mac


def get_device_interfaces_w_mac(router_name : str, interfaces : list) -> dict:
    interface_info = {}

    for interface in interfaces:
        interface_name = f"{router_name}-{interface['name']}"

        interface_info[interface_name] = {
            'mac': get_interface_mac(interface_name),
            'ip' : interface['ip']
        }

    return interface_info

class OSPF:
    def __init__(self, name : str, config_path : str, interface : Interface) -> None:
        """
        OSPF router inicializálása.
        :param name: A router neve, ahogyan a hálózatban szerepel
        :param config_path: Az OSPF konfiguráció elérési útja
        """
        self.router_name = name

        config = get_config(config_path)['routers'][router_name]

        self.rid        = config['rid']
        self.areaid     = config['area']
        self.interfaces = get_device_interfaces_w_mac(self.router_name, config['interfaces'])

        self.lsdb             = LSDB()
        self.packet_queue     = queue.PriorityQueue()
        self.neighbour_states = {intf: [] for intf in self.interfaces}

        self.neighbour_states_lock = threading.Lock()
        self.lsa_sequence_number   = 0
        self.last_lsa_update       = dt.now()
        self.is_simulation_done    = False

        # Csinal egy logger-t, ami a router nevét tartalmazza
        self.logger            = setup_logger(self.router_name)
        self.network_interface = interface


    def _send_hello(self, intf : str) -> None:
        """
        OSPF Hello csomag küldése multicast címen.
        :param intf: Az az interfész, amelyik küldi a csomagot
        :return:
        """
        while True:
            hello_packet = self._create_hello_packet(intf)

            self.network_interface.send(packet= hello_packet, interface= intf)
            utils.write_pcap_file(pcap_file= f'{intf}', packet= hello_packet)

            self.logger.info(f"Hello csomag küldve {intf} interfészen")
            logging.info(f"[{dt.now()}] Hello csomag küldve {intf} interfészen")

            sleep(HELLO_INTERVAL)

    def _create_hello_packet(self, intf):
        if self.neighbour_states[intf]:
            neighbour_list = [
                neighbour.rid for neighbour in self.neighbour_states[intf]
                if neighbour.state != States.DOWN
            ]
        else:
            neighbour_list = []

        packet = (
                Ether(
                    dst=MULTICAST_MAC,
                    src=self.interfaces[intf]['mac']
                ) /
                IP(
                    dst=MULTICAST_IP,
                    src=self.interfaces[intf]['ip'],
                    proto=89
                ) /
                OSPF_Hdr(
                    version=2,
                    type=1,
                    src=self.rid,
                    area=self.areaid

                ) /
                OSPF_Hello(
                    hellointerval=HELLO_INTERVAL,
                    deadinterval=DEAD_INTERVAL,
                    neighbors=neighbour_list
                )
        )

        return packet

    def _process_hello(self, intf : str, packet : Packet) -> None:
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

                logging.info(f"[{dt.now()}] {intf} szomszéd INIT: {neighbour.rid}")
                self.logger.info(f"{intf} szomszéd INIT: {neighbour.rid}")

            neighbour.last_seen = dt.now()

            if self.rid in packet[OSPF_Hello].neighbors and neighbour.state == States.INIT:
                neighbour.state = States.TWOWAY

                logging.info(f"[{dt.now()}] {intf} szomszéd 2-WAY: {neighbour.rid}")
                self.logger.info(f"{intf} szomszéd 2-WAY: {neighbour.rid}")

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

    def _listen(self, intf : str) -> None:
        """
        Az adott interfész figyel, és ha kap egy csomagot, akkor azt belerakja a packet queue-ba.
        :param intf: Az az interfész, amelyik figyeli a csomagokat
        :return:
        """
        while True:
            packet = self.network_interface.receive(interface= intf)

            if packet and packet.haslayer(OSPF_Hdr):
                self.packet_queue.put((intf, packet))
                utils.write_pcap_file(f'{intf}', packet)


    def _process_packet(self) -> None:
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

            if self.rid != packet[OSPF_Hdr].src:
                logging.info(f"[{dt.now()}] Csomag érkezett a(z) {intf} interfészen: {packet.summary()}")
                self.logger.info(f"Csomag érkezett a(z) {intf} interfészen: {packet.summary()}")

            header_type = packet[OSPF_Hdr].type

            if header_type == 1:  # Hello csomag
                self._process_hello(intf, packet)
            if header_type == 4: # LSUpdate csomag
                print(packet.show())
                #self.process_lsu(packet)

    def _state_watch(self, intf : str) -> None:
        """
        Interfészenként megnézzük a szomszédok állapotát és frissítjük azt.
        :param intf: Az aktuális router azon interfésze, amelyiket nézzük
        :return:
        """
        while True:
            self.check_timeout()

            with self.neighbour_states_lock:
                for neighbour in list(self.neighbour_states[intf]):
                    if neighbour.state == States.TWOWAY:
                        neighbour.state = States.EXSTART

                        logging.info(f"[{dt.now()}] {intf} szomszéd EXSTART: {neighbour.rid}")
                        self.logger.info(f"{intf} szomszéd EXSTART: {neighbour.rid}")

                    if neighbour.state == States.EXSTART:
                        neighbour.state = States.EXCHANGE

                        logging.info(f"[{dt.now()}] {intf} szomszéd EXCHANGE: {neighbour.rid}")
                        self.logger.info(f"{intf} szomszéd EXCHANGE: {neighbour.rid}")

                    if neighbour.state == States.EXCHANGE:
                        neighbour.state = States.LOADING

                        logging.info(f"[{dt.now()}] {intf} szomszéd LOADING: {neighbour.rid}")
                        self.logger.info(f"{intf} szomszéd LOADING: {neighbour.rid}")

                    if neighbour.state == States.LOADING:
                        neighbour.state = States.FULL
                        #self.generate_router_lsa()
                        #self.flood_lsa()

                        logging.info(f"[{dt.now()}] {intf} szomszéd FULL: {neighbour.rid}")
                        self.logger.info(f"{intf} szomszéd FULL: {neighbour.rid}")

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

                        logging.info(f'[{dt.now()}] {intf} NEIGHBOUR DOWN: {neighbour.display()}')

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

    def check_timeout(self) -> None:
        if self.lsdb.get_all() and self.last_lsa_update + td(seconds=TIMEOUT) < dt.now():
            self.is_simulation_done = True

    def start(self) -> None:

        threads = []
        for interface in self.interfaces:
            hello_thread       = threading.Thread(target=self._send_hello, args=(interface,))
            listening_thread   = threading.Thread(target=self._listen, args=(interface,))
            # is_down_thread   = threading.Thread(target=self.is_down, args=(interface,))
            state_watch_thread = threading.Thread(target=self._state_watch, args=(interface,))

            threads.extend([
                hello_thread,
                listening_thread,
                # is_down_thread,
                #state_watch_thread
            ])

        process_thread = threading.Thread(target=self._process_packet)
        threads.append(process_thread)

        for thread in threads:
            thread.start()
            #pass

if __name__ == '__main__':
    path = 'config/router.yml'

    router_name = sys.argv[1]
    network_interface = Interface()

    cleanup()

    ospf = OSPF(router_name, path, network_interface)
    ospf.start()
