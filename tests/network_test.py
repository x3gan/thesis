import logging
import os
from time import sleep

import pytest

from network.network_manager import NetworkManager
from network.topology import Topology
from common.utils import get_config


def test_empty_topology():
    """Teszt 1: Ha megvannak a szükséges paraméterek, betölti a konfigurációt."""
    test_empty_config = get_config('tests/config/network_test1.yml')

    test_topology = Topology(config= test_empty_config)

    assert test_topology.config == test_empty_config, "Nem tudott létrejönni a topológia."


def test_config_topology():
    """Teszt 2: A konfigurációs fájl alapján a topológiába kerülnek a routerek és a linkek."""
    test_router_config = get_config('tests/config/network_test2.yml')

    test_topology = Topology(config= test_router_config)

    assert test_topology.hosts() == ['R1', 'R2'], "Hiba a topológia létrehozása közben."
    assert test_topology.links() == [('R1', 'R2')], "Hiba a kapcsolatok bellítása közben."


@pytest.mark.skipif(os.getuid() != 0, reason="Mininet requires root")
def test_network_manager_create():
    """Teszt 3: Létrejön a NetworkManager a Mininet virtuális hálózattal."""
    test_network_manager = NetworkManager()

    assert test_network_manager._topology, "Nem tudott létrejönni a topológia."
    assert not test_network_manager._log_monitor._running, "Nem tudott elindulni a LogMonitor."


@pytest.mark.skipif(os.getuid() != 0, reason="Mininet requires root")
def test_router_network_manager():
    """Teszt 4: A virtuális hálózatban résztvevő routerek interfészei a konfigurációs fájl
    alapján állítódtak be."""
    test_network_manager = NetworkManager()
    error_msg = "Hibás konfiguráció."

    try:
        r1_eth0 = test_network_manager._network.getNodeByName('R1').intf('R1-eth0')
        r2_eth0 = test_network_manager._network.getNodeByName('R2').intf('R2-eth0')

        assert r1_eth0.name == 'R1-eth0', error_msg
        assert r1_eth0.ip == '10.0.0.1', error_msg
        assert r2_eth0.name == 'R2-eth0', error_msg
        assert r2_eth0.up == '10.0.0.3', error_msg
    except Exception as e:
        logging.error(f'Hiba a teszt futtatása közben: {e}')



@pytest.mark.skipif(os.getuid() != 0, reason="Mininet requires root")
def test_ospf_start():
    """Teszt 5: Ha elindul a NetworkManager, elindul az OSPF is a routereken."""
    test_network_manager = NetworkManager()
    test_network_manager._network.start()
    test_network_manager._start_ospf()

    sleep(5)

    r1 = test_network_manager._network.getNodeByName('R1')

    running_processes = r1.cmd("ps aux | grep '[o]spf'")
    assert "python3" in running_processes, f"OSPF nem fut R1-en. Folyamatok: {running_processes}"
