import logging
import os
import sys
from time import sleep

from mininet.cli import CLI
from mininet.net import Mininet

from monitoring.log_monitor import LogMonitor
from .topology import Topology
from common.utils import get_config

CONFIG_PATH = 'config/router.yml'

class NetworkManager:
    """A virtuális hálózat és az OSPF indításának kezelője.

    Itt jön létre a topológia, a hálózat és a naplófájlfigyelő. Itt indítódnak el az OSPF
    folyamatok a routereken. Az indulásnak két módja van: 'automatikus' és 'manuális'.

    Attribútumok:
        _config (dict):  Betöltött hálózati konfiguráció.
        _topology (Topology): Mininet topológia.
        _network (Mininet): Mininet hálózati példány.
        _logmonitor (LogMonitor): Naplófigyelő példány.
    """

    def __init__(self) -> None:
        self._config      = get_config(CONFIG_PATH)
        self._topology    = Topology(self._config)
        self._is_running  = False
        try:
            self._network     = Mininet(
                topo= self._topology
            )
        except Exception:
            logging.error(" Már fut másik Mininet folyamat: Futtassa a 'sudo mn -c' parancsot, "
                          "hogy leállítsd a sikertelenül leállt folyamatot. ")

        self._log_monitor = LogMonitor(
            log_dir='logs'
        )

    def run(self, mode: str) -> None:
        """Elindítja a hálózatot és az OSPF algoritmust minden routeren.

        Elindítja a Mininet hálózati példányt és a megadott módtól függően elindítja az  OSPF
        folyamatokat a routeren. Ha nincs mód megadva alapértelmezetten

        Paraméterek:
            mode (str): Indítás mód ('auto' vagy 'manual').
        """
        try:
            self._network.start()
            self._configure_interfaces()
            print("***** A hálózat elindult. *****")

            if mode == 'auto':
                self._log_monitor.start()
                print("***** A LogMonitor elindult. *****")

            if mode == 'auto':
                self._start_ospf()
            else:
                CLI(self._network)

            while self._is_running:
                sleep(0.5)
        except KeyboardInterrupt:
            self._log_monitor.stop()
            if mode == 'auto':
                print("A leállításhoz írjon 'exit'-et.")
                CLI(self._network)

            print("\n***** Kilépés... *****")
        finally:
            self._is_running = False
            self._log_monitor.stop()
            self._network.stop()
            print("***** A hálózat leállt. *****")

    def _start_ospf(self) -> None:
        """Elindítja az OSPF folyamatokat.

        A hálózatban szereplő összes routeren elindítja az OSPF folyamatokat.
        """
        for router in self._network.hosts:
            router.cmd(f"sudo PYTHONPATH={os.getcwd()} python3 -m ospf_core.ospf {router.name} &")

        self._is_running = True

    def _configure_interfaces(self) -> None:
        """Konfigurálja a routerek interfészeit.

        A konfigurációs fájl alapján beállítja a routerek interfészeinek az IP-címét.
        """
        for router in self._network.hosts:
            if router.name in self._config['routers']:
                for interface in self._config['routers'][router.name]['interfaces']:
                    interface_name = f"{router.name}-{interface['name']}"

                    router.setIP(interface['ip'], intf= interface_name)