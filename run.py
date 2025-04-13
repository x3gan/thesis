import sys

from mininet.cli import CLI
from mininet.net import Mininet

from topology import Topology
from utils import get_config

def configure_router_interfaces(net, config):
    for router in net.hosts:
        for interface, ip in config['router'][router.name]['interfaces'].items():
            router.setIP(ip, intf= interface)

def draw_topology():
    pass
    #     if folder
    # iter files
    # topo = Digraph(comment= 'routername')
    # for router in lsdb
#     for router , lsa quad
# topo edge cost

# print()

if __name__ == '__main__':
    mode = sys.argv[1] # man auto test

    router_config   = get_config('config/router.yml')
    topology_config = get_config('config/topology.yml')

    network = Mininet(topo= Topology(router_config, topology_config))
    network.start()

    configure_router_interfaces(network, router_config)


    if mode == 'auto':
        for router in network.hosts:
            router.cmd(f'sudo python3 ospf.py {router.name} &')

    CLI(network)


    network.stop()