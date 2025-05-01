from datetime import datetime as dt

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_Router_LSA, OSPF_Link, OSPF_LSUpd
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from ospf_core.neighbour import Neighbour
from ospf_core.ospf import OSPF
from ospf_core.state import State

CONFIG_PATH_2 = 'tests/config/ospf_test2.yml'


class MockInterface:
    def __init__(self):
        """Mock interész."""
        pass

class MockInfoLogger:
    def __init__(self):
        self.logger = self

    def info(self, msg):
        """Mock info metódus."""
        pass


def test_ospf_initialization():
    """Teszt 1: Unit teszt - Létrejön az OSPF-et kezelő osztály a konfigurációs fájl alapján"""
    mock_interface = MockInterface()
    mock_logger = MockInfoLogger()

    test_ospf = OSPF(
        name= 'RT',
        config_path='tests/config/ospf_test1.yml',
        interface= mock_interface,
        info_logger= mock_logger
    )

    error_msg = "Hiba a konfiguráció beolvasása közben."

    assert test_ospf._rid == '1.1.1.1', error_msg
    assert test_ospf._areaid == '0.0.0.0', error_msg
    assert test_ospf.router_name == 'RT', error_msg
    assert 'RT-eth0' in test_ospf._interfaces, error_msg


def test_hello_packet_creation():
    """Teszt 2: Unit teszt - Létrejön az OSPF Hello csomagot."""
    mock_interface = MockInterface()
    mock_logger = MockInfoLogger()

    test_ospf = OSPF(
        name= 'RT',
        config_path= CONFIG_PATH_2,
        interface= mock_interface,
        info_logger= mock_logger
    )
    test_ospf.interfaces = {
        'RT-eth0': {
            'mac' : '00:00:00:00:00:01',
            'ip'  : '10.0.0.1'
        }
    }

    test_hello_packet = test_ospf._create_hello_packet('RT-eth0')

    error_msg = "Hiba a Hello csomag létrehozása közben."

    assert test_hello_packet.haslayer(OSPF_Hdr), error_msg
    assert test_hello_packet.haslayer(OSPF_Hello), error_msg
    assert test_hello_packet[IP].dst == '224.0.0.5', error_msg
    assert test_hello_packet[OSPF_Hdr].src == '1.1.1.1', error_msg
    assert test_hello_packet[OSPF_Hdr].type == 1, error_msg
    assert test_hello_packet[OSPF_Hello].hellointerval == 10, error_msg
    assert test_hello_packet[OSPF_Hello].deadinterval == 40, error_msg

def test_hello_packet_processing():
    """Teszt 3: Unit teszt - Feldolgozza a beérkezett OSPF csomagot."""
    mock_interface = MockInterface()
    mock_logger = MockInfoLogger()

    test_ospf = OSPF(
        name='RT',
        config_path= CONFIG_PATH_2,
        interface=mock_interface,
        info_logger=mock_logger
    )
    test_ospf.interfaces = {
        'RT-eth0': {
            'mac': '00:00:00:00:00:01',
            'ip': '10.0.0.1'
        }
    }

    test_hello_packet = (
            Ether(
                src= '00:00:00:00:00:02',
                dst= '01:00:5e:00:00:05'
            ) /
            IP(
                src= '10.0.0.2',
                dst= '224.0.0.5',
                proto= 89
            ) /
            OSPF_Hdr(
                version= 2,
                type= 1,
                src= '2.2.2.2',
                area= '0.0.0.0'
            ) /
            OSPF_Hello(
                hellointerval= 10,
                deadinterval= 40,
                neighbors= []
            )
    )

    test_ospf._process_hello('RT-eth0', test_hello_packet)

    error_msg = "Hiba a Hello csomag feldolgozása közben,"

    assert 'RT-eth0' in test_ospf._neighbour_table, error_msg
    assert len(test_ospf._neighbour_table['RT-eth0']) == 1, error_msg
    assert test_ospf._neighbour_table['RT-eth0'][0].rid == '2.2.2.2', error_msg
    assert test_ospf._neighbour_table['RT-eth0'][0].ip == '10.0.0.2', error_msg
    assert test_ospf._neighbour_table['RT-eth0'][0].state.name == 'INIT', error_msg


def test_lsa_packet_creation():
    """Teszt 4: Unit teszt -  LSA létrehozása."""
    mock_interface = MockInterface()
    mock_logger = MockInfoLogger()

    test_ospf = OSPF(
        name='RT',
        config_path= CONFIG_PATH_2,
        interface=mock_interface,
        info_logger=mock_logger
    )

    test_ospf.interfaces = {
        'RT-eth0': {
            'mac': '00:00:00:00:00:01',
            'ip': '10.0.0.1'
        }
    }

    test_neighbour = Neighbour()
    test_neighbour.build(
        rid= '2.2.2.2',
        ip= '10.0.0.2',
        mac= '00:00:00:00:00:02',
        last_seen= dt.now(),
        state= State.FULL
    )

    test_ospf._neighbour_table['RT-eth0'] = [test_neighbour]

    test_ospf._generate_router_lsa()

    error_msg = "Hiba a Router LSA létrehozása közben."

    test_lsa_packet = test_ospf._lsdb.get(test_ospf._rid, 1)
    assert test_lsa_packet is not None, error_msg
    assert test_lsa_packet[OSPF_Router_LSA].adrouter == test_ospf._rid, error_msg
    assert test_lsa_packet[OSPF_Router_LSA].seq == 0, error_msg
    assert test_lsa_packet[OSPF_Router_LSA].linkcount == 1, error_msg
    assert test_lsa_packet[OSPF_Router_LSA].linklist[0].id == '2.2.2.2', error_msg


def test_lsu_packet_creation():
    """Teszt 5: Unit teszt - Létrehozza az LS Update csomagot."""
    mock_interface = MockInterface()
    mock_logger = MockInfoLogger()

    test_ospf = OSPF(
        name='RT',
        config_path= CONFIG_PATH_2,
        interface=mock_interface,
        info_logger=mock_logger
    )

    test_ospf.interfaces = {
        'RT-eth0': {
            'mac': '00:00:00:00:00:01',
            'ip': '10.0.0.1'
        }
    }

    test_link = (
        OSPF_Link(
            type= 1,
            id= '2.2.2.2',
            data= '10.0.0.2',
            metric= 1
        )
    )

    test_lsa_packet = (
        OSPF_Router_LSA(
            id= test_ospf._rid,
            adrouter= test_ospf._rid,
            linkcount= 1,
            linklist= [test_link]
        )
    )

    test_neighbour = Neighbour()
    test_neighbour.build(
        rid='2.2.2.2',
        ip='10.0.0.2',
        mac='00:00:00:00:00:02',
        last_seen=dt.now(),
        state=State.FULL
    )

    test_ospf._lsdb.add(test_lsa_packet)

    erro_msg = "Hiba az LSU csomag létrehozása közben."

    test_lsu_packet = test_ospf._create_lsu_packet('RT-eth0', test_neighbour, [test_lsa_packet])

    assert test_lsu_packet.haslayer(OSPF_Hdr), erro_msg
    assert test_lsu_packet.haslayer(OSPF_LSUpd), erro_msg
    assert test_lsu_packet[OSPF_Hdr].type == 4, erro_msg
    assert len(test_lsu_packet[OSPF_LSUpd].lsalist) == 1, erro_msg
    assert test_lsu_packet[OSPF_LSUpd].lsalist[0].adrouter == "1.1.1.1", erro_msg

def test_lsa_packet_processing():
    """Teszt 6: Unit teszt - Feldolgozza az LSU-ban kapott LSA-t és frissíti az LSDB-t."""
    mock_interface = MockInterface()
    mock_logger = MockInfoLogger()

    test_ospf = OSPF(
        name='RT',
        config_path= CONFIG_PATH_2,
        interface=mock_interface,
        info_logger=mock_logger
    )

    test_ospf.interfaces = {
        'RT-eth0': {
            'mac': '00:00:00:00:00:01',
            'ip': '10.0.0.1'
        }
    }

    test_link = (
        OSPF_Link(
            type= 1,
            id= '1.1.1.1',
            data= '10.0.0.1',
            metric= 1
        )
    )

    test_lsa_packet = (
        OSPF_Router_LSA(
            id= '2.2.2.2',
            adrouter= '2.2.2.2',
            seq= 1,
            linkcount= 1,
            linklist= [test_link]
        )
    )

    test_result = test_ospf._process_lsa(test_lsa_packet)

    error_msg = "Hiba a Router LSA feldolgozása közben."

    test_existing_lsa = test_ospf._lsdb.get('2.2.2.2', 1)
    assert test_result is True, error_msg
    assert test_existing_lsa[OSPF_Router_LSA].adrouter == '2.2.2.2', error_msg
    assert test_existing_lsa[OSPF_Router_LSA].seq == 1, error_msg
    assert test_existing_lsa[OSPF_Router_LSA].linkcount == 1, error_msg
    assert test_existing_lsa[OSPF_Router_LSA].linklist[0].id == '1.1.1.1', error_msg