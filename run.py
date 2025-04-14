import sys

from mininet.cli import CLI
from mininet.net import Mininet

from log_monitor import LogMonitor
from topology import Topology
from utils import get_config

def configure_router_interfaces(net, config):
    for router in net.hosts:
        for interface, ip in config['router'][router.name]['interfaces'].items():
            router.setIP(ip, intf= interface)

if __name__ == '__main__':
    mode = sys.argv[1] # man auto test

    router_config   = get_config('config/router.yml')
    topology_config = get_config('config/topology.yml')

    network = Mininet(topo= Topology(router_config, topology_config))

    log_monitor = LogMonitor()

    try:
        network.start()

        configure_router_interfaces(network, router_config)

        log_monitor.start()

        CLI(network)

    finally:
        log_monitor.stop()
        network.stop()