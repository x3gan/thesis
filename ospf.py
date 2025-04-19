import os
import sys
import queue
import logging
import threading
import networkx as nx

from time import sleep
from yaml import safe_load
from datetime import timedelta as td
from datetime import datetime as dt

from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_Router_LSA, OSPF_LSUpd, OSPF_Link

from lsdb import LSDB
from state import State
from neighbour import Neighbour
from interface import Interface
from monitoring.info_logger import InfoLogger
from monitoring.pcap_logger import PcapLogger


MULTICAST_IP = '224.0.0.5'
MULTICAST_MAC = '01:00:5e:00:00:05'

TIMEOUT        = 10
DEAD_INTERVAL  = 40
HELLO_INTERVAL = 10

CONFIG_PATH = 'config/router.yml'
INFO_LOG_DIR = 'logs'

def get_config(filepath):
    with open(filepath, 'r') as file:
        config = safe_load(file)

    return config


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

    def __init__(self, name : str, config_path : str, interface : Interface, info_logger: InfoLogger) -> None:
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
        self.packet_queue     = queue.Queue()
        self.neighbour_states = {intf: [] for intf in self.interfaces}
        self.routing_table    = {}

        self.neighbour_states_lock = threading.Lock()
        self.lsa_sequence_number   = 0
        self.last_lsa_update       = dt.now()
        self.is_simulation_done    = False

        # Csinal egy logger-t, ami a router nevét tartalmazza
        self._info_logger       = info_logger.logger
        self._pcap_logger       = PcapLogger()
        self.network_interface  = interface
        self.topology           = nx.Graph()

    def _send_hello(self, intf : str) -> None:
        """
        OSPF Hello csomag küldése multicast címen.
        :param intf: Az az interfész, amelyik küldi a csomagot
        :return:
        """
        while True:
            hello_packet = self._create_hello_packet(intf)

            self.network_interface.send(packet= hello_packet, interface= intf)
            self._pcap_logger.write_pcap_file(pcap_file= f'{intf}', packet= hello_packet)

            self._info_logger.info(f" Hello csomag küldve {intf} interfészen")

            sleep(HELLO_INTERVAL)

    def _create_hello_packet(self, intf: str) -> Packet:
        if self.neighbour_states[intf]:
            neighbour_list = [
                neighbour.rid for neighbour in self.neighbour_states[intf]
                if neighbour.state != State.DOWN
            ]
        else:
            neighbour_list = []

        packet = (
                Ether(
                    dst= MULTICAST_MAC,
                    src= self.interfaces[intf]['mac']
                ) /
                IP(
                    dst= MULTICAST_IP,
                    src= self.interfaces[intf]['ip'],
                    proto= 89
                ) /
                OSPF_Hdr(
                    version= 2,
                    type= 1,
                    src= self.rid,
                    area= self.areaid

                ) /
                OSPF_Hello(
                    hellointerval= HELLO_INTERVAL,
                    deadinterval= DEAD_INTERVAL,
                    neighbors= neighbour_list
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

            neighbour = self._get_neighbour(intf, neighbour_rid)

            if neighbour is None:
                neighbour = self._create_neighbour(neighbour_rid, neighbour_ip, neighbour_mac)
                self.neighbour_states[intf].append(neighbour)

                self._info_logger.info(f" {intf} szomszéd INIT: {neighbour.rid}")

            neighbour.last_seen = dt.now()

            if self.rid in packet[OSPF_Hello].neighbors and neighbour.state == State.INIT:
                neighbour.state = State.TWOWAY

                self._info_logger.info(f" {intf} szomszéd 2-WAY: {neighbour.rid}")

    def _get_neighbour(self, intf : str, src : str) -> Neighbour | None:
        for neighbour in self.neighbour_states[intf]:
            if neighbour.rid == src:
                return neighbour

        return None

    @staticmethod
    def _create_neighbour(rid : str, ip : str, mac : str) -> Neighbour:
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
            state     = State.INIT
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
                self._pcap_logger.write_pcap_file(f'{intf}', packet)

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
                self._info_logger.info(f" Csomag érkezett a(z) {intf} interfészen: {packet.summary()}")

            header_type = packet[OSPF_Hdr].type

            if header_type == 1:  # Hello csomag
                self._process_hello(intf, packet)
            if header_type == 4: # LSUpdate csomag
                self._process_lsu(packet)

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
                    if neighbour.state == State.TWOWAY:
                        sleep(1)
                        neighbour.state = State.EXSTART

                        self._info_logger.info(f" {intf} szomszéd EXSTART: {neighbour.rid}")

                    if neighbour.state == State.EXSTART:
                        sleep(1)
                        neighbour.state = State.EXCHANGE

                        self._info_logger.info(f" {intf} szomszéd EXCHANGE: {neighbour.rid}")

                    if neighbour.state == State.EXCHANGE:
                        sleep(1)
                        neighbour.state = State.LOADING

                        self._info_logger.info(f" {intf} szomszéd LOADING: {neighbour.rid}")

                    if neighbour.state == State.LOADING:
                        sleep(1)
                        neighbour.state = State.FULL
                        self._generate_router_lsa()
                        self._flood_lsa()

                        self._info_logger.info(f" {intf} szomszéd FULL: {neighbour.rid}")

            sleep(1)

    def _generate_router_lsa(self) -> None:
        """
        Legeneraljuk az aktualis router LSA-jet, minden interfeszen, minden szomszeddal es ezt
        beletesszuk a router LSDB-jebe.
        :return:
        """
        link_type = 1

        links = []
        for intf, neighbours in self.neighbour_states.items():
            for neighbour in neighbours:
                if neighbour.state == State.FULL:
                    link = OSPF_Link(
                        type   = link_type,
                        id     = neighbour.rid,
                        data   = self.interfaces[intf]['ip'],
                        metric = 1
                    )
                    links.append(link)

        lsa = OSPF_Router_LSA(
                id        = self.rid,
                adrouter  = self.rid,
                seq       = self.lsa_sequence_number,
                linkcount = len(links),
                linklist  = links
        )

        self.lsa_sequence_number += 1
        self.lsdb.add(lsa)

        print(self.lsdb.get_all())

    def _flood_lsa(self, intf = None, exclude_rid = None) -> None:
        if not self.lsdb.get(self.rid, 1):
            self._generate_router_lsa()

        if intf is None:
            for intf in self.interfaces:
                self._flood_lsa(intf)
            return

        lsa_list = self.lsdb.get_all()

        for neighbour in self.neighbour_states[intf]:
            if neighbour.state == State.FULL and neighbour.rid != exclude_rid:

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

                self._pcap_logger.write_pcap_file(pcap_file= f'{intf}', packet= lsu_packet)

                self._info_logger.info(f" LSUpdate csomag küldve {intf} interfészen")

    def _is_down(self, intf: str) -> None:
        while True:
            with self.neighbour_states_lock:
                for neighbour in list(self.neighbour_states[intf]):
                    if (neighbour.state != State.DOWN and
                        neighbour.last_seen + td(seconds= DEAD_INTERVAL) < dt.now()):
                        self.neighbour_states[intf].remove(neighbour)

                        self._info_logger.info(f" Elvesztett a {neighbour.rid} szomszéddal a kapcsolat a(z) {intf} interfészen")

            sleep(2)

    def _process_lsu(self, packet : Packet) -> None:
        lsa_list    = packet[OSPF_LSUpd].lsalist
        lsa_updated = False

        for lsa in lsa_list:
            if self._process_lsa(lsa):
                lsa_updated = True

        if lsa_updated:
            self._run_spf()
            self._show_topology()
            self._flood_lsa(exclude_rid= packet[OSPF_Hdr].src)

    def _process_lsa(self, lsa : Packet) -> bool:
        """
        LSA feldolgozása, ha még nem tároltunk róla információt vagy a beérkező információ újabb
        mint az általunk ismert, akkor frissítjük a LSDB-t.

        :param lsa: A beérkező LSA csomag
        :return:
        """
        sender_rid = lsa[OSPF_Router_LSA].adrouter
        lsa_type   = lsa[OSPF_Router_LSA].type

        existing_lsa = self.lsdb.get(sender_rid, lsa_type)


        if not existing_lsa or lsa.seq > existing_lsa.seq:
            self.lsdb.add(lsa)
            print(self.lsdb.get_all())
            self.last_lsa_update = dt.now()

            self._info_logger.info(f" {self.router_name} LSDB frissítve: {lsa.summary()}")

            return True

        return False

    def _build_topology(self) -> None:
        """
        A LSDB-ből kiolvassuk az összes router LSA-t és azok linkjeit, majd ezeket felhasználva
        felépítjük a topológiát.

        :return:
        """
        self.topology.clear()

        for lsa in self.lsdb.get_all():
            if not isinstance(lsa, OSPF_Router_LSA):
                continue

            for link in lsa.linklist:
                self.topology.add_edge(
                    u_of_edge= lsa.adrouter,
                    v_of_edge= link.id,
                    weight    = link.metric
                )

    def _run_spf(self) -> None:
        """
        Meghívja a NetworkX Python könyvtárat és annak segítségével kiszámolja a legrövidebb utat minden Router szempontjából.
        (Támogatja az egyforma költségű utakkal való számolást is)
        :return:
        """
        self._build_topology()

        source = self.rid

        try:
            paths = nx.shortest_path(
                G= self.topology,
                source= source,
                target= None,
                weight= 'weight'
            )

            distances = nx.shortest_path_length(
                G= self.topology,
                source= source,
                weight= 'weight'
            )

            self.routing_table = {}
            for target, path in paths.items():

                if target == self.rid:
                    continue

                self.routing_table[target] = {
                    'cost' : distances[target],
                    'next_hop' : path[1]
                }

                self._info_logger.info(f" Legjobb útvonal {source} -> {target}: Út: {path}, Költség: {distances[target]}")

        except nx.NetworkXNoPath:
            logging.error(f"Nincs elérhető útvonal a(z) {self.router_name} egyetlen szomszédjához sem.")
            return

    def _show_topology(self) -> None:
        for line in nx.generate_network_text(self.topology):
            self._info_logger.info(line)

    def check_timeout(self) -> None:
        if self.lsdb.get_all() and self.last_lsa_update + td(seconds=TIMEOUT) < dt.now():
            self.is_simulation_done = True

    def start(self) -> None:
        self._pcap_logger.cleanup(self.router_name, log_dir= 'packet_logs')

        threads = []
        for interface in self.interfaces:
            hello_thread       = threading.Thread(target= self._send_hello, args= (interface,))
            listening_thread   = threading.Thread(target= self._listen, args= (interface,))
            is_down_thread     = threading.Thread(target= self._is_down, args= (interface,))
            state_watch_thread = threading.Thread(target= self._state_watch, args= (interface,))

            threads.extend([
                hello_thread,
                listening_thread,
                is_down_thread,
                state_watch_thread
            ])

        process_thread = threading.Thread(target= self._process_packet)
        threads.append(process_thread)

        for thread in threads:
            thread.start()

if __name__ == '__main__':
    router_name = sys.argv[1]
    network_interface = Interface()
    info_logger = InfoLogger(router_name, INFO_LOG_DIR)

    ospf = OSPF(router_name, CONFIG_PATH, network_interface, info_logger)
    ospf.start()
