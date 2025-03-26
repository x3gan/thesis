from mininet.cli import CLI
from mininet.net import Mininet

from topology import Topology
from utils import get_config

def configure_router_interfaces(net, config):
    for router in net.hosts:
        for interface, ip in config['router'][router.name]['interfaces'].items():
            router.setIP(ip, intf= interface)

if __name__ == '__main__':
    router_config   = get_config('router.yml')
    topology_config = get_config('topology.yml')

    network = Mininet(topo= Topology(router_config, topology_config))
    network.start()

    configure_router_interfaces(network, router_config)

    CLI(network)
    network.stop()