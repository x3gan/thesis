import logging
import sys

from mininet.cli import CLI
from mininet.net import Mininet

from monitoring.log_monitor import LogMonitor
from topology import Topology
from common.utils import get_config

CONFIG_PATH = 'config/router.yml'

class NetworkManager:

    def __init__(self) -> None:
        self._config      = get_config(CONFIG_PATH)
        self._topology    = Topology(self._config)
        try:
            self._network     = Mininet(
                topo= self._topology
            )
        except Exception:
            logging.error(" Már fut másik Mininet folyamat: Futtasd a 'sudo mn -c' parancsot, "
                          "hogy leállítsd a sikertelenül leállt folyamatot. ")

        self._log_monitor = LogMonitor(
            log_dir= 'logs'
        )

    def run(self, mode : str = 'manual') -> None:
        """Elindítja a hálózatot és az OSPF algoritmust minden routeren.

        Parameters:
        mode (str): Az elindítás módja.
            manual: Az OSPF algoritmust manuálisan kell a routerek termináljában elindítani.
            auto: Az algoritmus elindul magától, csak a kimenetet kell figyelni.
        """
        try:
            self._network.start()
            self._configure_interfaces()
            print("***** A hálózat elindult. *****")

            if mode == 'auto':
                self._start_ospf()

            self._log_monitor.start()
            print("***** A LogMonitor elindult. *****")

            CLI(self._network)
        except KeyboardInterrupt:
            print("\n***** Kilépés... *****")
        finally:
            self._log_monitor.stop()
            self._network.stop()
            print("***** A hálózat leállt. *****")

    def _start_ospf(self) -> None:
        """Elindítja az OSPF kódját a routereken."""
        for router in self._network.hosts:
            router.cmd(f"sudo python3 ospf.py {router.name} &")

    def _configure_interfaces(self) -> None:
        """Konfigurálja a hálózati eszközök interfészeit."""
        for router in self._network.hosts:
            if router.name in self._config['routers']:
                for interface in self._config['routers'][router.name]['interfaces']:
                    interface_name = f"{router.name}-{interface['name']}"

                    router.setIP(interface['ip'], intf= interface_name)

if __name__ == '__main__':
    mode = sys.argv[1]

    network_manager = NetworkManager()
    network_manager.run(mode)