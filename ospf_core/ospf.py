import logging
import os
import queue
import sys
import threading
import time
from datetime import datetime as dt
from datetime import timedelta as td
from time import sleep

import networkx as nx
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_Router_LSA, OSPF_LSUpd, OSPF_Link
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from common.utils import get_config
from monitoring.info_logger import InfoLogger
from monitoring.pcap_logger import PcapLogger
from network.scapy_interface import ScapyInterface
from ospf_core.lsdb import LSDB
from ospf_core.neighbour import Neighbour
from ospf_core.state import State

# ---------------------------------------
# Konstansok és konfigurációk
# ---------------------------------------

MULTICAST_IP  = '224.0.0.5'
MULTICAST_MAC = '01:00:5e:00:00:05'

DEAD_INTERVAL  = 40
HELLO_INTERVAL = 10
MAX_QUEUE_SIZE = 1000

CONFIG_PATH  = 'config/router.yml'
INFO_LOG_DIR = 'logs'


# ---------------------------------------
# Segédfüggvények
# ---------------------------------------

def get_interface_mac(name: str) -> str:
    """Kiolvassuk az interfész információkat.

    A virtuális rendszerfájlból kiolvassuk a hálózati interfész MAC címét, letisztítjuk,
    majd visszaadjuk.

    Parameterek:
        name (str) : Az interfész neve.

    Visszatérési érték:
        mac (str) : Az interfész kiolvasott MAC címe.
    """
    try:
        mac = os.popen(f"cat /sys/class/net/{name}/address").read().strip()
        return mac
    except FileNotFoundError:
        logging.error(f" Interfész {name} nem található.0")
        return ""
    except Exception as e:
        logging.error(f" Váratlan hiba a MAC cím olvasásakor: {str(e)}")
        return ""


def get_interface_status(interface: str) -> bool:
    """Visszaadja az interfész állapotát.

    Az aktuális router termináljában futtatja a parancsot és lekéri az interfészeiről az
    információt. Majd visszaadja a paraméterként kapott interfésznek mi az aktuális állapota.

    Paraméterek:
        interface (str) : A router azon interfészének neve aminek az állapotára kiváncsiak vagyunk.

    Visszatérési érték:
        status (bool) : True-t ad vissza, ha a kért interfész UP állapotban van.
    """
    status = False
    try:
        with open(f'/sys/class/net/{interface}/operstate') as f:
            if 'up' in f.read().lower():
                status = True
            return status
    except FileNotFoundError:
        logging.error(f"Interfész {interface} nem található.")
        return status
    except Exception as e:
        logging.error(f"Váratlan hiba az interfész ellenőrzése közben: {str(e)}")
        return status


def get_device_interfaces_w_mac(name: str, interfaces: list) -> dict:
    """Létrehoz egy interfész szótárt.

    A konfigurációban megadott interfészeket összepaárosítja a routerrel és kikeresi hozzá a MAC
    címet.

    Paraméterek:
        name (str): A router neve.
        interfaces (list): A router konfigurációjához megadott
    """
    interface_info = {}

    for interface in interfaces:
        interface_name = f"{name}-{interface['name']}"

        interface_info[interface_name] = {
            'mac': get_interface_mac(interface_name),
            'ip': interface['ip']
        }

    return interface_info


def set_routing_table(routing_table: dict) -> None:
    """Routing tábla alapján az útvonal hozzáadása a routerhez."""
    try:
        if None in routing_table.values():
            logging.error(" Hiba a routing tábla beállítása közben. Leállás...")
            return

        for route in routing_table.values():
            try:
                os.system(f"ip route del {route['destination']}")
                os.system(f"ip route add {route['destination']} via {route['next_hop']} dev {route['interface']}")
            except Exception as e:
                logging.error(f" Hiba a routing tábla frissítése közben: {str(e)}")

    except Exception as e:
        logging.error(f" Váratlan hiba a routing tábla beállítása közben: {str(e)}")



class OSPF:
    """ A routereken futó OSPF algoritmus logikája.

    Kezeli a különböző hálózati csomagok küldését, fogadását és feldolgozását. Eltárolja a
    szomszédokkal való kapcsolat aktuális állapotát és figyeli azok változásait. Figyeli ha
    változás történik a topológiában (eltűnik kapcsolat vagy megjelenik új) és értesíti róla
    szomszédait.

    Attribútumok:
        _router_name (str) : A router neve, ahogy a hálózatban megtalálható.
        _rid (str) : A router egyedi azonosítója, ezen a néven terjeszti a csomagokat.
        _areaid (str) : A hálózati terület azonosítója, fontos szerepet játszik a beérkező csomagok validációjában.
        _interfaces (dict) : A router interfészeinek neve, IP címe és MAC címe.
        _lsdb (LSDB) : A router legalább FULL állapotban lévő szomszédainak adatait tárolja.
        _packet_queue (queue.Queue) : A beérkező hálózati csomagok feldolgozási sora.
        _neighbour_table (dict) : A szomszédról tárol adatot a megismerése pillanatától fogva.
        _routing_table (dict) : Az SPF algoritmus által kiszámolt routing adatokat tárolja.
        _neigbhour_states_Lock (threading.RLock) : A _neighbour_table szótár zárolására.
        _lsa_sequence_number (int) : Számon tarja a router által generált LSA-k szekvencia számát, hogy el lehessen dönteni melyik a 'legfrissebb'.
        _last_lsa_update (datetime) : Eltárolja mikor érkezett új olyan LSA, amit eltárolunk.
        _stop_event (threading.Event) : Jelzi az OSPF folyamatoknak, hogy le kell állniuk.
        _threads (dict) : Tárolja az egy routeren futó OSPF folyamatok szálait tárolja.
        is_running (bool) : Jelzi, hogy az adott routeren fut-e OSPF folyamat.
        _lsa_seq_number_lock (threading.Lock) : Zárolja az LSA szekvenciaszámát, a szálbiztonság érdekében.
        _interfaces_lock (threading.Lock) : A szálbiztonság érdekében zárolja az interfészeket tartalmazó szótárat.
        _info_logger (InfoLogger): A routerek naplófájl-írójának egy példánya.
        _pcap_logger (PcapLogger): A hálózati csomag naplózó egy példánya.
        _network_interface (ScapyInterface): Az interfészeken történő közvetlen kommunikációt kezelő osztály.
        _topology (nx.Graph): A router által felismert topológia.
    """

    def __init__(self, name: str, config_path: str, interface: ScapyInterface, info_logger: InfoLogger) -> None:
        self._router_name = name

        self._config = get_config(config_path)['routers'][self._router_name]

        self._rid        = self._config['rid']
        self._areaid     = self._config['area']
        self._interfaces = get_device_interfaces_w_mac(self._router_name, self._config['interfaces'])

        self._lsdb             = LSDB()
        self._packet_queue     = queue.Queue(maxsize= MAX_QUEUE_SIZE)
        self._neighbour_table = {intf: [] for intf in self._interfaces}
        self._routing_table    = {}
        self._topology         = nx.Graph()

        self._neighbour_table_global_lock = threading.RLock()
        self._neighbour_table_lock        = {intf: threading.RLock() for intf in self._interfaces}
        self._lsa_seq_number_lock          = threading.Lock()
        self._interfaces_lock             = threading.Lock()
        self._lsdb_lock                   = threading.RLock()
        self._routing_table_lock          = threading.RLock()
        self._topology_lock               = threading.RLock()

        self._lsa_sequence_number  = 0
        self.last_lsa_update      = dt.now()
        self._stop_event          = threading.Event()
        self._threads             = {}
        self._intf_monitor_thread = None
        self._process_thread      = None

        self.is_running = False

        self._info_logger      = info_logger.logger
        self._pcap_logger      = PcapLogger()
        self._network_interface = interface

    # ----------------------------------------------
    # Hálózati csomagok kezelése
    # ----------------------------------------------

    def _listen(self, intf: str) -> None:
        """Hallgatja az interfészt az OSPF csomagokért.

        Az adott interfész figyel, és ha kap egy csomagot, akkor azt belerakja a packet queue-ba.

        Paraméterek:
            intf (str) : Az az interfész, amelyiken figyeljuk a hálózati csomagokat.
        """
        while not self._stop_event.is_set():
            if get_interface_status(intf):
                packet = self._network_interface.receive(interface=intf)

                if packet and packet.haslayer(OSPF_Hdr):
                    self._packet_queue.put((intf, packet), timeout= 1)
                    self._pcap_logger.write_pcap_file(f"{intf}", packet)

    def _process_packet(self) -> None:
        """Típustól függően feldologzza a sorban lévő hálózati csomagokat.

        A packet queue-ból sorra olvassuk ki a csomagokat és típustól függően tovább küldi
        feldolgozásra őket.
        """
        while not self._stop_event.is_set():
            try:
                intf, packet = self._packet_queue.get(timeout=1)
            except queue.Empty:
                continue

            if self._rid != packet[OSPF_Hdr].src:
                self._info_logger.info(
                    f" Csomag érkezett a(z) {intf} interfészen: {packet.summary()}")

            header_type = packet[OSPF_Hdr].type

            if packet[OSPF_Hdr].version != 2:
                break

            if header_type == 1:  # Hello csomag
                self._process_hello(intf, packet)
            if header_type == 4:  # LSUpdate csomag
                self._process_lsu(packet)

    # ----------------------------------------------
    # Hello csomagok kezelése
    # ----------------------------------------------

    def _create_hello_packet(self, intf: str) -> Packet:
        """Hello csomagok létrehozása.

        A küldő router interfészének az információji alapján és a router nem DOWN somszédai
        alapján csinál Hello csomagot.

        Paraméterek:
            intf (str): Annak az interfésznek a neve, amelyik küldi a csomagot.

        Visszatérési érték:
            packet (Packet): A Hello csomag.
        """
        with self._neighbour_table_lock[intf]:
            if self._neighbour_table[intf]:
                neighbour_list = [
                    neighbour.rid for neighbour in self._neighbour_table[intf]
                    if neighbour.state != State.DOWN
                ]
            else:
                neighbour_list = []

        packet = (
                Ether(
                    dst=MULTICAST_MAC,
                    src=self._interfaces[intf]['mac']
                ) /
                IP(
                    dst=MULTICAST_IP,
                    src=self._interfaces[intf]['ip'],
                    proto=89
                ) /
                OSPF_Hdr(
                    version=2,
                    type=1,
                    src=self._rid,
                    area=self._areaid

                ) /
                OSPF_Hello(
                    hellointerval=HELLO_INTERVAL,
                    deadinterval=DEAD_INTERVAL,
                    neighbors=neighbour_list
                )
        )

        return packet

    def _send_hello(self, intf: str) -> None:
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
                self._network_interface.send(packet=hello_packet, interface=intf)
                self._pcap_logger.write_pcap_file(pcap_file=f'{intf}', packet=hello_packet)

                self._info_logger.info(f" Hello csomag küldve {intf} interfészen")

            if self._stop_event.wait(timeout=HELLO_INTERVAL):
                break

    def _process_hello(self, intf: str, packet: Packet) -> None:
        """Feldolgozza a Hello típusú csomagokat.

        A sorból kivett csomagot típus szerint Hello csomagként feldolgozza. Kiszedi a küldő
        router információit az OSPF rétegekből és tárolja el róla az információkat a
        _neighbour_table szótárba.

        Paraméterek:
            intf (str): Annak az interfésznek a neve, amelyik kapta a csomagot.
            packet (Packet): A feldolgozandó Hello csomag.
        """

        if not self._is_valid_hello_packet(packet):
            return

        neighbour_rid = packet[OSPF_Hdr].src
        neighbour_ip = packet[IP].src
        neighbour_mac = packet[Ether].src

        with self._neighbour_table_lock[intf]:
            neighbour = self._get_neighbour(intf, neighbour_rid)

            if neighbour is None:
                neighbour = self._create_neighbour(neighbour_rid, neighbour_ip, neighbour_mac)
                self._neighbour_table[intf].append(neighbour)

                self._info_logger.info(f" {intf} szomszéd INIT: {neighbour.rid}")

            neighbour.last_seen = dt.now()

            if self._rid in packet[OSPF_Hello].neighbors and neighbour.state == State.INIT:
                neighbour.state = State.TWOWAY

                self._info_logger.info(f" {intf} szomszéd 2-WAY: {neighbour.rid}")

    def _is_valid_hello_packet(self, packet: Packet) -> bool:
        """Ellenőrzi, hogy a Hello csomag hiteles-e.

        Paraméterek:
            packet (Packet): A Hello csomag.

        Visszatérési érték:
            _ (bool): Hiteles-e az ellenőrzött csomag
        """
        if (
                packet.haslayer(OSPF_Hello) and
                packet[OSPF_Hdr].area == self._areaid and
                packet[OSPF_Hello].hellointerval == HELLO_INTERVAL and
                packet[OSPF_Hello].deadinterval == DEAD_INTERVAL and
                packet[IP].dst == MULTICAST_IP and
                packet[OSPF_Hdr].src != self._rid
        ):
            return True
        return False

    # ----------------------------------------------
    # LSUpdate csomagok kezelése
    # ----------------------------------------------

    def _generate_router_lsa(self) -> None:
        """Router LSA generálása.

        Legenerálja a saját router LSA-t, minden interfészen, minden szomszéddal eltárolja a
        kapcsolatait és az LSA-ba, amit az LSDB-ben tárol.
        """
        link_type = 1

        links = []

        for intf, neighbours in self._neighbour_table.items():
            with self._neighbour_table_lock[intf]:

                for neighbour in neighbours:
                    if neighbour.state == State.FULL:
                        link = OSPF_Link(
                            type= link_type,
                            id= neighbour.rid,
                            data= self._interfaces[intf]['ip'],
                            metric= 1
                        )
                        links.append(link)

        with self._lsa_seq_number_lock, self._lsdb_lock:

            existing_lsa = self._lsdb.get(self._rid, link_type)
            if existing_lsa:
                self._lsa_sequence_number = existing_lsa.seq + 1
            else:
                self._lsa_sequence_number = 0

            lsa = OSPF_Router_LSA(
                id= self._rid,
                adrouter= self._rid,
                seq= self._lsa_sequence_number,
                linkcount= len(links),
                linklist= links
            )

            self._lsa_sequence_number += 1
            self._lsdb.add(lsa)

    def _create_lsu_packet(self, intf: str, neighbour: Neighbour, lsa_list: list) -> Packet:
        """Létrehozza az LSU csomagot az adott interfészre.

        Paraméterek:
            intf (str): Az az interfész, amelyiken kuldeni akarjuk a csomagot.
            neighbour (Neigbhour): A szomszéd.
            lsa_list (list): A küldendő LSA-k listája.

        Visszatérési érték:
            packet (Packet): A létrejött LSU csomag.
        """
        packet = (
                Ether(
                    dst=neighbour.mac,
                    src=self._interfaces[intf]['mac']
                ) /
                IP(
                    dst=neighbour.ip,
                    src=self._interfaces[intf]['ip'],
                    proto=89
                ) /
                OSPF_Hdr(
                    version=2,
                    type=4,
                    src=self._rid,
                    area=self._areaid
                ) / OSPF_LSUpd(
            lsalist=lsa_list
        )
        )

        return packet

    def _flood_lsa(self, intf: str = None, exclude_rid: str = None) -> None:
        """LSA-k terjesztése.

        Paraméterek:
            intf (str): Az interfész amelyiken küldi a csomagot.
            exclude_rid (str): Az az interfész amelyiktől azt a csomagot kapta amit
            tovább terjeszt.
        """

        if intf is None:
            with self._interfaces_lock:
                interfaces = list(self._interfaces.keys())
            for intf in interfaces:
                self._flood_lsa(intf)
            return

        with self._lsdb_lock:
            if not self._lsdb.get(self._rid, 1):
                self._generate_router_lsa()

            lsa_list = self._lsdb.get_all()

        with self._neighbour_table_lock[intf]:
            neighbours = list(self._neighbour_table[intf])

        for neighbour in neighbours:
            if neighbour.state == State.FULL and neighbour.rid != exclude_rid:
                lsu_packet = self._create_lsu_packet(intf, neighbour, lsa_list)

                if get_interface_status(intf):
                    self._network_interface.send(packet=lsu_packet, interface=intf)
                    self._pcap_logger.write_pcap_file(pcap_file=f'{intf}', packet=lsu_packet)

                    self._info_logger.info(f" LSUpdate csomag küldve {intf} interfészen")

    def _process_lsu(self, packet: Packet) -> None:
        """LSUpdate csomag feldolgozása

        Paraméterek:
            packet (Packet): Az LSU csomag.
        """
        lsa_list = packet[OSPF_LSUpd].lsalist
        lsa_updated = False

        for lsa in lsa_list:
            if self._process_lsa(lsa):
                lsa_updated = True

        if lsa_updated:
            self._run_spf()
            self._show_topology()
            self._flood_lsa(exclude_rid=packet[OSPF_Hdr].src)

    def _process_lsa(self, lsa: Packet) -> bool:
        """LSA-k feldolgozása

        LSA feldolgozása, ha még nem tároltunk róla információt vagy a beérkező információ újabb
        mint az általunk ismert, akkor frissítjük a LSDB-t.

        Paraméterek:
            lsa (Packet): A beérkező LSA csomag.

        Visszatérési érték:
            _ (bool): Történt-e LSDB frissítés.
        """
        sender_rid = lsa[OSPF_Router_LSA].adrouter
        lsa_type = lsa[OSPF_Router_LSA].type

        with self._lsdb_lock:
            existing_lsa = self._lsdb.get(sender_rid, lsa_type)

            if not existing_lsa or lsa.seq > existing_lsa.seq:
                self._lsdb.add(lsa)
                self.last_lsa_update = dt.now()

                self._info_logger.info(f" {self._router_name} LSDB frissítve: {lsa.summary()}")

                return True

        return False

    # ----------------------------------------------
    # Szomszédok állapotának kezelése
    # ----------------------------------------------

    def _is_down(self, intf: str) -> None:
        """Szomszédok elérhetőségét ellenőrzi.

        Paraméterek:
            intf (str): Az interfész ahol nézzük a szomszéd állapotát.

        """
        while not self._stop_event.is_set():
            with self._neighbour_table_lock[intf]:
                for neighbour in list(self._neighbour_table[intf]):
                    if neighbour.state != State.DOWN and neighbour.last_seen + td(seconds=DEAD_INTERVAL) < dt.now():
                        neighbour.state = State.DOWN

                        with self._lsdb_lock:
                            self._lsdb.remove(neighbour.rid, 1)
                        self._info_logger.info(f" Elvesztett a {neighbour.rid} szomszéddal a kapcsolat a(z) {intf} interfészen")
                        self._generate_router_lsa()
                        self._run_spf()
                        self._show_topology()
                        self._flood_lsa()

            if self._stop_event.wait(timeout=DEAD_INTERVAL):
                break

    def _state_watch(self, intf: str) -> None:
        """Interfészek állapotváltása.

        Interfészenként megnézzük a szomszédok állapotát és frissítjük azt.

        Paraméterek:
            intf (str): Az aktuális router azon interfésze, amelyiket nézzük
        Megjegyzés:
            - A simább állapotváltás érdekében mindig várunk legalább 1 másodpercet.
            - LOADING állapotban: Adatbázis szinkronizációt szimulálunk.

        """
        state_map = {
            State.TWOWAY : State.EXSTART,
            State.EXSTART : State.EXCHANGE,
            State.EXCHANGE : State.LOADING,
            State.LOADING : State.FULL
        }

        while not self._stop_event.is_set():
            with self._neighbour_table_lock[intf]:
                neighbours = list(self._neighbour_table[intf])

            for neighbour in neighbours:
                current_state = neighbour.state

                if current_state in state_map:
                    new_state = state_map[current_state]

                    if self._stop_event.wait(timeout=1):
                        break

                    neighbour.state = new_state
                    self._info_logger.info(f" {intf} szomszéd {new_state.name}: {neighbour.rid}")

                    if new_state == State.FULL:
                        self._info_logger.info(f" LSDB szinkronizáció sikeres a(z) {neighbour.rid} szomszéddal")

                        self._generate_router_lsa()
                        self._run_spf()
                        self._show_topology()
                        self._flood_lsa()

    # ----------------------------------------------
    # Somszédok kezelése
    # ----------------------------------------------

    def _get_neighbour(self, intf: str, src: str) -> Neighbour | None:
        """Kikeresi a szomszédot a szótárból.

        Kikeresi a szomszéd adatait a szomszéd RID-ja és az alapján az interfész alapján,
        ahol megismertük.

        Paraméterek:
            intf (str): Az interfész, ahol megismertük a szomszédot.
            src (str): A szomszéd RID-ja.

        Visszatérési érték:
            neigbhour (Neighbour | None): Ha megtalalálja a keresett szomszéd adatait, visszadja.
        """
        for neighbour in self._neighbour_table[intf]:
            if neighbour.rid == src:
                return neighbour

        return None

    @staticmethod
    def _create_neighbour(rid: str, ip: str, mac: str) -> Neighbour:
        """Szomszéd létrehozása.

        A Hello csomagban kapott adatok alapján létrehoz egy szomszéd példányt.

        Paraméterek:
            rid (str) : A szomszéd router ID-ja.
            ip (str) : A szomszéd IP címe.
            mac (str) : A szomszéd MAC címe.

        Visszatérési érték:
            neigbhour (Neigbhour): A Hello csomagban kapott adatok alapján INIT állapotba kerülő
            szomszéd példány.
        """
        neighbour = Neighbour()

        neighbour.build(
            rid=rid,
            ip=ip,
            mac=mac,
            last_seen=dt.now(),
            state=State.INIT
        )

        return neighbour

    # ----------------------------------------------
    # Topológia és legrövidebb út
    # ----------------------------------------------

    def _build_topology(self) -> None:
        """Topológia információk megszerzése LSDB alapján.

        A LSDB-ből kiolvassuk az összes router LSA-t és azok linkjeit, majd ezeket felhasználva
        felépítjük a topológiát.
        """

        with self._lsdb_lock, self._topology_lock:
            self._topology.clear()

            for lsa in self._lsdb.get_all():
                if not isinstance(lsa, OSPF_Router_LSA):
                    continue

                self._topology.add_node(lsa.adrouter)

                for link in lsa.linklist:
                    self._topology.add_edge(
                        u_of_edge= lsa.adrouter,
                        v_of_edge= link.id,
                        weight= link.metric
                    )

    def _run_spf(self) -> None:
        """Legrövidebb út kiszámítása.

        Meghívja a NetworkX Python könyvtárat és annak segítségével kiszámolja a legrövidebb utat minden Router szempontjából.
        (Támogatja az egyforma költségű utakkal való számolást is)
        """
        self._build_topology()

        source = self._rid

        try:
            paths = nx.shortest_path(
                G= self._topology,
                source= source,
                target= None,
                weight= 'weight'
            )

            distances = nx.shortest_path_length(
                G= self._topology,
                source= source,
                weight= 'weight'
            )

            self._routing_table = {}
            for target, path in paths.items():

                if target == self._rid:
                    continue

                intf = self._get_interface_by_rid(path[1])
                with self._neighbour_table_lock[intf]:
                    neigbhour = self._get_neighbour(intf= intf, src=path[1])

                self._routing_table[target] = {
                    'destination' : neigbhour.ip,
                    'cost'        : distances[target],
                    'next_hop'    : neigbhour.ip,
                    'interface'   : intf
                }

                set_routing_table(self._routing_table)

                self._info_logger.info(
                    f" Legjobb útvonal {source} -> {target}: Út: {path}, Költség: {distances[target]}")

        except nx.NetworkXNoPath:
            logging.error(
                f"Nincs elérhető útvonal a(z) {self._router_name} egyetlen szomszédjához sem.")
            return

    def _get_interface_by_rid(self, rid: str) -> str | None:
        """Kikeresi a megadott szomszédhoz tartozó interfészt.

        Paraméterek:
            rid (str): A keresett szomszéd

        Megjegyzés:
            - Melyik szomszédot, melyik interfészen fedeztük fel.
        """
        for intf, _ in self._neighbour_table.items():
            with self._neighbour_table_lock[intf]:

                for neighbour in self._neighbour_table[intf]:
                    if neighbour.rid == rid:
                        return intf
        return None


    def _show_topology(self) -> None:
        """Topológia megjelenítése

        Az eltárolt topológiai információkat átadja az InfoLogger-nek, hogy a terminálban
        megjeleníthető legyen.
        """

        with self._topology_lock:
            for line in nx.generate_network_text(self._topology):
                self._info_logger.info(line)

    # ----------------------------------------------
    # Életciklus kezelése (indítás és megállítás)
    # ----------------------------------------------

    def _intf_monitor(self):
        """Figyeli és kezeli a router interfészeinek állapotát.

        Ellenőrzi, hogy az itnerfész 'UP' vagy 'DOWN' állapotban van-e. Ha 'UP' és még nem fut rajta
        OSPF elindítjuk, ha 'DOWN' és fut rajta OSPF akkor azt leállítjuk az adott interfészen.
        """
        while not self._stop_event.is_set():
            for intf in self._interfaces:
                state = get_interface_status(intf)

                if state and intf not in self._threads:
                    self._start_ospf_threads(intf=intf)

                elif not state and intf in self._threads:
                    self._remove_intf_data(intf= intf)
                    self._stop_ospf_threads(intf=intf)

            time.sleep(5)

    def _remove_intf_data(self, intf: str) -> None:
        """Interfészen szerzett adatok törlése.

        Interfész leállása esetén eltávolít minden információt amit az adott interfészen szerzett.

        Paraméterek:
            intf (str): Interfész neve.
        """
        with self._neighbour_table_lock[intf], self._lsdb_lock:

            neigbhours = [
                neighbour.rid for neighbour in self._neighbour_table[intf]
            ]
            self._neighbour_table[intf].clear()

            for neighbour_rid in neigbhours:
                self._lsdb.remove(neighbour_rid, 1)

    def _start_ospf_threads(self, intf: str) -> None:
        """Elindítja az adott router OSPF folyamatait kezelő szálakat,"""
        if intf in self._threads or not get_interface_status(intf):
            return
        
        self._threads[intf] = {
            'listen': threading.Thread(target=self._listen, args=(intf,),
                                       name=f"ListenerThread-{intf}"),
            'hello': threading.Thread(target=self._send_hello, args=(intf,),
                                      name=f"HelloThread-{intf}"),
            'down': threading.Thread(target=self._is_down, args=(intf,),
                                     name=f"DownThread-{intf}"),
            'state': threading.Thread(target=self._state_watch, args=(intf,),
                                      name=f"StateWatchThread-{intf}")
        }

        for thread in self._threads[intf].values():
            try:
                thread.start()
            except Exception as e:
                self._info_logger.error(f" Hiba a {thread.name} szal elinditasa kozben: {str(e)}")
                self._stop_ospf_threads(intf= intf)

    def start(self) -> None:
        """Elindítja az OSPF folyamatot.

        Kitörli a hálózati csomagok log fájljait és visszaállítja a leállítási event flag-et.
        Létrehozza a szükséges threadeket és az azokon futó folyamatokat, majd elindítja azokat.
        """
        self._pcap_logger.cleanup(self._router_name)
        self._stop_event.clear()
        self._threads.clear()

        for interface in self._interfaces:
            if get_interface_status(interface):
                self._start_ospf_threads(interface)

        self._intf_monitor_thread = threading.Thread(target=self._intf_monitor,
                                                     name='InterfaceMonitorThread')
        self._intf_monitor_thread.start()

        self._process_thread = threading.Thread(target=self._process_packet,
                                                name='PacketProcessorThread')
        self._process_thread.start()

        self.is_running = True
        self._info_logger.info("Az OSPF elindult.")

    def _stop_ospf_threads(self, intf: str) -> None:
        """OSPF szálak leállítása.

        Ha van olyan interéfsz amiken fut OSPF, akkor leállítjuk a szálakat.
        """
        if intf not in self._threads:
            return

        for thread in self._threads[intf].values():
            if thread.is_alive():
                thread.join(timeout=2.0)

        del self._threads[intf]
        self._info_logger.info(f"Az {intf} leallitotta az  OSPF-et.")

    def stop(self) -> None:
        """OSPF leállítása a routeren.

        Beállítja a _stop_event-et, ezzel jelezve a folyamatoknak, hogy le kell állni. Leállítja
        az interfész figyelőt, az OSPF folyamatokat és a csomag feldolgozót.
        """
        self._stop_event.set()

        try:
            self._intf_monitor_thread.join(timeout=2.0)
        except Exception as e:
            self._info_logger.error(
                f"Hiba a {self._intf_monitor_thread.name} szal leallitasa kozben: {str(e)}")

        for intf in list(self._threads.keys()):
            self._stop_ospf_threads(intf)

        try:
            self._process_thread.join(timeout=2.0)
        except Exception as e:
            self._info_logger.error(f"Hiba a {self._process_thread.name} szal leallitasa kozben: {str(e)}")

        self.is_running = False


if __name__ == '__main__':
    router_name = sys.argv[1]
    info_logger = InfoLogger(name=router_name, log_dir=INFO_LOG_DIR)
    scapy_interface = ScapyInterface()

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