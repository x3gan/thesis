from datetime import datetime as dt
import logging
import queue
import sys
import threading
from time import sleep

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_Router_LSA, OSPF_LSUpd, OSPF_LSA_Hdr, \
    OSPF_Link
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff
from sympy.solvers.diophantine.diophantine import length

import utils
from lsdb import LSDB
from neighbour import Neighbour
from states import States

MULTICAST_IP = '224.0.0.5'
MULTICAST_MAC = '01:00:5e:00:00:05'

HELLO_INTERVAL = 10
DEAD_INTERVAL = 40

logging.basicConfig(level=logging.INFO)


class OSPF:
    def __init__(self, name, config_path):
        self.name = name

        ospf_config = utils.get_config(config_path)['ospf'][self.name]

        self.interfaces = utils.get_device_interfaces_w_mac()
        self.rid = ospf_config['rid']
        self.areaid = ospf_config['areaid']

        self.neighbour_states = {intf: [] for intf in self.interfaces}
        self.lsdb = LSDB()
        self.packet_queue = queue.PriorityQueue()

        self.neighbour_states_lock = threading.Lock()

    def send_hello(self, intf):
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
                        neighbors= neighbour_list,
                    )
            )

            sendp(x= hello_packet, iface= intf, verbose= False)
            utils.write_pcap_file(pcap_file= f'{self.name}-{intf}', packet= hello_packet)

            logging.info(f'[{dt.now()}] {self.name} - {intf} HELLO')

            sleep(HELLO_INTERVAL)

    def generate_router_lsa(self):
        lsa_type = 1

        links = []
        for intf, neighbours in self.neighbour_states.items():
            for neighbour in neighbours:
                if neighbour.state == States.FULL:
                    link = OSPF_Link(
                        id     = neighbour.rid,
                        data   = self.interfaces[intf]['ip'],
                        type   = 1,
                        metric = 1

                    )
                    links.append(link)

        lsa = (
            OSPF_LSA_Hdr(
                adrouter  = self.rid,
                id = self.rid
            ) /
            OSPF_Router_LSA(
                type      = lsa_type,
                id        = self.rid,
                adrouter  = self.rid,
                linklist  = links
            )
        )


        self.lsdb.add(lsa)
        self.flood_lsa()

    def flood_lsa(self, intf = None):
        if intf is None:
            for intf in self.interfaces:
                self.flood_lsa(intf)
            return

        for neighbour in self.neighbour_states[intf]:
            if neighbour.state == States.FULL:
                lsa = self.lsdb.get(self.rid, self.rid) #is string

                lsa_packet = (
                        Ether(
                            dst=neighbour.mac,
                            src=self.interfaces[intf]['mac']
                        ) /
                        IP(
                            dst=neighbour.ip,
                            src=self.interfaces[intf]['ip'],
                            proto=89
                        ) /
                        OSPF_Hdr(
                            version=2,
                            type=4,
                            src=self.rid,
                            area=self.areaid
                        ) /
                        OSPF_LSUpd(
                            lsalist=lsa
                        )
                )

                utils.write_pcap_file(pcap_file= f'{self.name}-{intf}', packet= lsa_packet)
                sendp(x= lsa_packet, iface= intf, verbose= False)

                logging.info(f'[{dt.now()}] {self.name} - {intf} LSUpdate')


    def listen(self, intf):
        while True:
            packets = sniff(iface= intf, count= 1)

            if packets:
                packet = packets[0]

                if packet.haslayer(OSPF_Hdr):
                    self.packet_queue.put((intf, packet))
                    utils.write_pcap_file(f'{self.name}-{intf}', packet)

                    logging.info(f'[{dt.now()}] {self.name} - {intf} RECEIVED: {packet[0].summary()}')

    def is_down(self, intf):
        while True:
            with self.neighbour_states_lock:
                for neighbour in list(self.neighbour_states[intf]):
                    if neighbour.state == States.DOWN:
                        self.neighbour_states[intf].remove(neighbour)

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR DOWN: {neighbour.display()}')

            sleep(DEAD_INTERVAL)

    def process_packet(self):
        while True:
            try:
                intf, packet = self.packet_queue.get(timeout=1)
            except queue.Empty:
                continue

            header_type = packet[OSPF_Hdr].type

            if header_type == 1:  # Hello csomag
                self.process_hello(intf, packet)
            if header_type == 4:
                self.process_lsu(intf, packet)

    def process_lsu(self, intf, packet):
        print(packet.show())

    def process_hello(self, intf, packet):
        if packet[OSPF_Hdr].src == self.rid:
            return

        with self.neighbour_states_lock:
            neighbour = self.get_neighbour(intf, packet[OSPF_Hdr].src)

            if neighbour is None:
                neighbour = self.create_neighbour(intf, packet[OSPF_Hdr].src)
                self.neighbour_states[intf].append(neighbour)

                logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR INIT:'
                             f' {neighbour.display()}')

            neighbour.last_seen = dt.now()

            if self.rid in packet[OSPF_Hello].neighbors and neighbour.state == States.INIT:
                neighbour.state = States.TWOWAY

                logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR TWO-WAY:'
                             f' {neighbour.display()}')

    def get_neighbour(self, intf, src):
        for neighbour in self.neighbour_states[intf]:
            if neighbour.rid == src:
                return neighbour

        return None

    def create_neighbour(self, intf, src):
        neighbour = Neighbour()
        neighbour.build(
            rid= src,
            ip= self.interfaces[intf]['ip'],
            mac= self.interfaces[intf]['mac'],
            last_seen= dt.now(),
            state= States.INIT
        )

        return neighbour

    def state_watch(self, intf):
        while True:
            with self.neighbour_states_lock:
                for neighbour in list(self.neighbour_states[intf]):
                    if neighbour.state == States.TWOWAY:
                        neighbour.state = States.EXSTART

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR EX-START:'
                                     f' {neighbour.display()}')
                    if neighbour.state == States.EXSTART:
                        neighbour.state = States.EXCHANGE

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR EXCHANGE:'
                                     f' {neighbour.display()}')

                    if neighbour.state == States.EXCHANGE:
                        neighbour.state = States.LOADING

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR LOADING:'
                                     f' {neighbour.display()}')

                    if neighbour.state == States.LOADING:
                        neighbour.state = States.FULL
                        self.generate_router_lsa()

                        logging.info(f'[{dt.now()}] {self.name} - {intf} NEIGHBOUR FULL:'
                                     f' {neighbour.display()}')

            sleep(1)


if __name__ == '__main__':
    path = 'config/ospf.yml'

    router_name = sys.argv[1]

    utils.cleanup()

    ospf = OSPF(router_name, path)

    threads = []
    for interface in ospf.interfaces:
        hello_thread       = threading.Thread(target=ospf.send_hello, args=(interface,))
        listening_thread   = threading.Thread(target=ospf.listen, args=(interface,))
        is_down_thread     = threading.Thread(target=ospf.is_down, args=(interface,))
        state_watch_thread = threading.Thread(target=ospf.state_watch, args=(interface,))

        threads.extend([
            hello_thread,
            listening_thread,
            is_down_thread,
            state_watch_thread
        ])

    process_thread = threading.Thread(target=ospf.process_packet)
    threads.append(process_thread)

    for thread in threads:
        thread.start()