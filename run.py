import sys

from mininet.cli import CLI
from mininet.net import Mininet

from log_monitor import LogMonitor
from topology import Topology
from utils import get_config

CONFIG_PATH = 'config/router.yml'

class NetworkManager:
    def __init__(self) -> None:
        self.config      = get_config(CONFIG_PATH)
        self.network     = Mininet(topo= Topology(self.config))
        self.log_monitor = LogMonitor()

    def run(self, mode : str = 'manual') -> None:
        try:
            self.network.start()
            self.configure_interfaces()

            if mode == 'auto':
                self.start_ospf()

            self.log_monitor.start()

            CLI(self.network)
        finally:
            self.log_monitor.stop()
            self.network.stop()

    def start_ospf(self) -> None:
        for router in self.network.hosts:
            router.cmd("sudo python3 ospf.py {router.name} &")

    def configure_interfaces(self) -> None:
        for router in self.network.hosts:
            if router.name in self.config['routers']:
                for interface in self.config['routers'][router.name]['interfaces']:
                    interface_name = f"{router.name}-{interface['name']}"

                    router.setIP(interface['ip'], intf= interface_name)

if __name__ == '__main__':
    mode = sys.argv[1] # man auto test

    network_manager = NetworkManager()
    network_manager.run(mode)