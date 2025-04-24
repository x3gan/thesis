import os
import sys
import queue
import logging
import threading
import time

import networkx as nx

from time import sleep
from datetime import timedelta as td
from datetime import datetime as dt

from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_Router_LSA, OSPF_LSUpd, OSPF_Link

from ospf_core.lsdb import LSDB
from ospf_core.neighbour import Neighbour
from ospf_core.state import State
from network.scapy_interface import ScapyInterface
from monitoring.info_logger import InfoLogger
from monitoring.pcap_logger import PcapLogger
from common.utils import get_config

# ---------------------------------------
# Konstansok és konfigurációk
# ---------------------------------------

MULTICAST_IP = '224.0.0.5'
MULTICAST_MAC = '01:00:5e:00:00:05'

DEAD_INTERVAL  = 40
HELLO_INTERVAL = 10
MAX_RETRIES    = 5

CONFIG_PATH = 'config/router.yml'
INFO_LOG_DIR = 'logs'


# ---------------------------------------
# Segédfüggvények
# ---------------------------------------

def get_interface_mac(name : str) -> str:
    """Kiolvassuk az interfész információkat.
    A virtuális rendszerfájlból kiolvassuk a hálózati interfész MAC címét, letisztítjuk,
    majd visszaadjuk.

    Parameterek:
        name (str) : Az interfész neve.

    Visszatérési érték:
        mac (str) : Az interfész kiolvasott MAC címe.
    """
    mac = os.popen(f"cat /sys/class/net/{name}/address").read().strip()
    return mac


def get_interface_status(interface: str) -> bool:
    """Visszaadja az interfész állapotát
    Az aktuális router termináljában futtatja a parancsot és lekéri az interfészeiről az
    információt. Majd visszaadja a paraméterként kapott interfésznek mi az aktuális állapota.

    Paraméterek:
        interface (str) : A router azon interfészének neve aminek az állapotára kiváncsiak vagyunk.

    Visszatérési érték:
        status (bool) : True-t ad vissza, ha a kért interfész UP állapotban van
    """
    status = False
    try:
        with open(f'/sys/class/net/{interface}/operstate') as f:
            if 'up' in f.read().lower():
                status = True
            return status
    except:
        return False


def get_device_interfaces_w_mac(name : str, interfaces : list) -> dict:
    interface_info = {}

    for interface in interfaces:
        interface_name = f"{name}-{interface['name']}"

        interface_info[interface_name] = {
            'mac': get_interface_mac(interface_name),
            'ip' : interface['ip']
        }

    return interface_info

def try_to_wake_up_intf(intf : str):
    up = False

    try:
        os.system(f"ip link set dev {intf} up 2>/dev/null")

        time.sleep(0.5)

        if get_interface_status(intf):
            up = True

        return up
    except Exception as e:
        ospf._info_logger.error(f"Hiba az interfesz aktivalasa kozben: {str(e)}")
        return False


class OSPF:
    """ A routereken futó OSPF algoritmus logikája.
    Kezeli a különböző hálózati csomagok küldését, fogadását és feldolgozását. Eltárolja a
    szomszédokkal való kapcsolat aktuális állapotát és figyeli azok változásait. Figyeli ha
    változás történik a topológiában (eltűnik kapcsolat vagy megjelenik új) és értesíti róla
    szomszédait.

    Attribútumok:
        _router_name (str) : A router neve, ahogy a hálózatban megtalálható
        _rid (str) : A router egyedi azonosítója, ezen a néven terjeszti a csomagokat
        _areaid (str) : A hálózati terület azonosítója, fontos szerepet játszik a beérkező csomagok validációjában
        _interfaces (dict) : A router interfészeinek neve, IP címe és MAC címe
        _lsdb (LSDB) : A router legalább FULL állapotban lévő szomszédainak adatait tárolja
        _packet_queue (queue.Queue) : A beérkező hálózati csomagok feldolgozási sora
        _neighbour_states (dict) : A szomszédról tárol adatot a megismerése pillanatától fogva
        _routing_table (dict) : Az SPF algoritmus által kiszámolt routing adatokat tárolja
        _neigbhour_states_Lock (threading.Lock) : A _neighbour_states szótár zárolására
        _lsa_sequence_number (int) : Számon tarja a router által generált LSA-k szekvencia számát, hogy el lehessen dönteni melyik a 'legfrissebb'

    """
    def __init__(self, name : str, config_path : str, interface : ScapyInterface, info_logger:
    InfoLogger) -> None:
        self.router_name = name

        config = get_config(config_path)['routers'][self.router_name]

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
        self._stop_event           = threading.Event()
        self._threads              = {}
        self._intf_monitor_thread  = None
        self._process_thread       = None
        self.is_running            = False

        self._info_logger       = info_logger.logger
        self._pcap_logger       = PcapLogger()
        self.network_interface  = interface
        self.topology           = nx.Graph()

    # ----------------------------------------------
    # Hálózati csomagok kezelése
    # ----------------------------------------------

    def _listen(self, intf : str) -> None:
        """Hallgatja az interfészt az OSPF csomagokért.
        Az adott interfész figyel, és ha kap egy csomagot, akkor azt belerakja a packet queue-ba.

        Paraméterek:
            intf (str) : Az az interfész, amelyiken figyeljuk a hálózati csomagokat.
        """
        while not self._stop_event.is_set():
            if get_interface_status(intf):
                packet = self.network_interface.receive(interface= intf)

                if packet and packet.haslayer(OSPF_Hdr):
                    self.packet_queue.put((intf, packet))
                    self._pcap_logger.write_pcap_file(f"{intf}", packet)

    def _process_packet(self) -> None:
        """
        A packet queue-bol sorra olvassuk ki a csomagokat és típustól függően tovább küldi
        feldolgozásra őket.
        :return:
        """
        while not self._stop_event.is_set():
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


    # ----------------------------------------------
    # Hello csomagok kezelése
    # ----------------------------------------------

    def _create_hello_packet(self, intf: str) -> Packet:
        """

        :param intf:
        :return:
        """
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

    def _send_hello(self, intf : str) -> None:
        """OSPF Hello csomag küldése multicast címen
        Amíg nem kap interrupt jelzést, HELLO_INTERVAL (10 mp) időközönként küldi a Hello
        csomagot a multicast címre, hogy mindenki hallja, hogy él és jelezze, hogy mely routerek
        a szomszédai. Ezzel a csomagküldéssel keresi az új szomszédokat.

        Paraméterek:
            intf (str) : Az az interfész, amelyiken kiküldi a csomagot
        """
        while not self._stop_event.is_set():
            hello_packet = self._create_hello_packet(intf)

            if get_interface_status(intf):
                self.network_interface.send(packet= hello_packet, interface= intf)
                self._pcap_logger.write_pcap_file(pcap_file= f'{intf}', packet= hello_packet)

                self._info_logger.info(f" Hello csomag küldve {intf} interfészen")

            if self._stop_event.wait(timeout= HELLO_INTERVAL):
                break

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


    # ----------------------------------------------
    # LSUpdate csomagok kezelése
    # ----------------------------------------------

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
                if get_interface_status(intf):
                    self.network_interface.send(packet= lsu_packet, interface= intf)
                    self._pcap_logger.write_pcap_file(pcap_file= f'{intf}', packet= lsu_packet)

                    self._info_logger.info(f" LSUpdate csomag küldve {intf} interfészen")

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
    

    # ----------------------------------------------
    # Szomszédok állapotának kezelése
    # ----------------------------------------------

    def _is_down(self, intf : str) -> None:
        while not self._stop_event.is_set():
            with self.neighbour_states_lock:
                for neighbour in list(self.neighbour_states[intf]):
                    if (neighbour.state != State.DOWN and
                        neighbour.last_seen + td(seconds= DEAD_INTERVAL) < dt.now()):
                        self.neighbour_states[intf].remove(neighbour)

                        self._info_logger.info(f" Elvesztett a {neighbour.rid} szomszéddal a kapcsolat a(z) {intf} interfészen")

            if self._stop_event.wait(timeout= DEAD_INTERVAL):
                break

    def _state_watch(self, intf : str) -> None:
        """
        Interfészenként megnézzük a szomszédok állapotát és frissítjük azt.
        :param intf: Az aktuális router azon interfésze, amelyiket nézzük
        :return:
        """
        while not self._stop_event.is_set():

            with self.neighbour_states_lock:
                for neighbour in list(self.neighbour_states[intf]):
                    if neighbour.state == State.TWOWAY:
                        if self._stop_event.wait(timeout=1):
                            break

                        neighbour.state = State.EXSTART

                        self._info_logger.info(f" {intf} szomszéd EXSTART: {neighbour.rid}")

                    if neighbour.state == State.EXSTART:
                        if self._stop_event.wait(timeout=1):
                            break

                        neighbour.state = State.EXCHANGE

                        self._info_logger.info(f" {intf} szomszéd EXCHANGE: {neighbour.rid}")

                    if neighbour.state == State.EXCHANGE:
                        if self._stop_event.wait(timeout=1):
                            break

                        neighbour.state = State.LOADING

                        self._info_logger.info(f" {intf} szomszéd LOADING: {neighbour.rid}")

                    if neighbour.state == State.LOADING:
                        if self._stop_event.wait(timeout=1):
                            break

                        neighbour.state = State.FULL
                        self._generate_router_lsa()
                        self._flood_lsa()

                        self._info_logger.info(f" {intf} szomszéd FULL: {neighbour.rid}")

            if self._stop_event.wait(timeout=1):
                break


    # ----------------------------------------------
    # Somszédok kezelése
    # ----------------------------------------------

    def _get_neighbour(self, intf : str, src : str) -> Neighbour | None:
        for neighbour in self.neighbour_states[intf]:
            if neighbour.rid == src:
                return neighbour

        return None

    @staticmethod
    def _create_neighbour(rid : str, ip : str, mac : str) -> Neighbour:
        """A Hello csomagban kapott adatok alapján létrehoz egy szomszéd példányt.

        Paraméterek:
        rid (str) : A szomszéd router ID-ja.
        ip (str) : A szomszéd IP címe.
        mac (str) : A szomszéd MAC címe.

        Visszatérési érték:
        A Hello csomagban kapott adatok alapján INIT állapotba kerülő syomsyéd példánz.
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


    # ----------------------------------------------
    # Topológia és legrövidebb út
    # ----------------------------------------------

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
        """Topológia megjelenítése
        Az eltárolt topológiai információkat átadja az InfoLogger-nek, hogy a terminálban
        megjeleníthető legyen.
        """
        for line in nx.generate_network_text(self.topology):
            self._info_logger.info(line)


    # ----------------------------------------------
    # Életciklus kezelése (indítás és megállítás)
    # ----------------------------------------------
    def _intf_monitor(self):
        while not self._stop_event.is_set():
            for intf in self.interfaces:
                state = get_interface_status(intf)

                if state and intf not in self._threads:
                    self._start_ospf_threads(intf= intf)

                if not state and intf in self._threads:
                    self._stop_ospf_threads(intf= intf)

            time.sleep(5)


    def _start_ospf_threads(self, intf : str):
        if intf in self._threads or not get_interface_status(intf):
            return

        self._threads[intf] = {
            'hello'   : threading.Thread(target= self._send_hello, args= (intf,),
                                              name= f"HelloThread-{intf}"),
            'listen'  : threading.Thread(target= self._listen, args= (intf,),
                                              name= f"ListenerThread-{intf}"),
            'down'    : threading.Thread(target= self._is_down, args= (intf,),
                                              name= f"DownThread-{intf}"),
            'state'   : threading.Thread(target= self._state_watch, args= (intf,),
                                              name= f"StateWatchThread-{intf}")
        }

        for thread in self._threads[intf].values():
            try:
                thread.start()
            except Exception as e:
                self._info_logger.error(f"Hiba a {thread.name} szal elinditasa kozben: {str(e)}")


    def start(self) -> None:
        """Elindítja az OSPF folyamatot.
        Tisztítja a hálózati csomagok log fájljait és visszaállítja a leállítási event flag-et.
        Létrehozza a szükséges threadeket és az azokon futó folyamatokat, majd elindítja azokat.
        """
        self._pcap_logger.cleanup(self.router_name, log_dir='packet_logs')
        self._stop_event.clear()
        self._threads.clear()

        for interface in self.interfaces:
            if get_interface_status(interface):
                self._start_ospf_threads(interface)

        self._intf_monitor_thread = threading.Thread(target= self._intf_monitor,
                                                     name= 'InterfaceMonitorThread')
        self._intf_monitor_thread.start()

        self._process_thread      = threading.Thread(target= self._process_packet,
                                          name= 'PacketProcessorThread')
        self._process_thread.start()

        self.is_running = True
        self._info_logger.info("Az OSPF elindult.")

    def _stop_ospf_threads(self, intf : str):
        if intf not in self._threads:
            return

        for thread in self._threads[intf].values():
            if thread.is_alive():
                thread.join(timeout= 2.0)

        del self._threads[intf]
        self._info_logger.info(f"Az {intf} leallitotta az  OSPF-et.")

    def stop(self) -> None:
        self._stop_event.set()

        try:
            self._intf_monitor_thread.join(timeout= 2.0)
        except Exception as e:
            self._info_logger.error(f"Hiba a {self._intf_monitor_thread.name} szal leallitasa kozben: "
                                    f"{str(e)}")

        for intf in list(self._threads.keys()):
            self._stop_ospf_threads(intf)

        try:
            self._process_thread.join(timeout= 2.0)
        except Exception as e:
            self._info_logger.error(f"Hiba a {self._process_thread.name} szal leallitasa kozben: "
                                    f"{str(e)}")

        self.is_running = False


if __name__ == '__main__':
    router_name       = sys.argv[1]
    info_logger       = InfoLogger(name= router_name, log_dir= INFO_LOG_DIR)
    scapy_interface   = ScapyInterface()

    ospf = OSPF(router_name, CONFIG_PATH, scapy_interface, info_logger)

    try:
        ospf.start()
        while ospf.is_running:
            sleep(0.5)
    except KeyboardInterrupt:
        print("\nLeállítási parancsot kapott... (CTRL + C)")
    except Exception as e:
        info_logger.logger.error(f"Varatlan hiba: {str(e)}")
    finally:
        ospf.stop()
        print("Az OSPF futása leállt.")