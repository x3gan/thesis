from mininet.cli import CLI
from mininet.net import Mininet

from topology import Topology
from utils import get_config

def configure_router_interfaces(net, config):
    """
    A router interfészeinek IP címének beállítása a konfigurációs fájl alapján.
    :param net: Virtualis hálózat peldany
    :param config: router konfigurációs fájl
    """
    for router in net.hosts:
        for interface, ip in config['router'][router.name]['interfaces'].items():
            router.setIP(ip, intf= interface)

if __name__ == '__main__':
    # Betolti a virtualis halozat felepitesehez szukseges konfiguraciokat
    router_config   = get_config('router.yml')
    topology_config = get_config('topology.yml')

    # A Mininet halozat letrehozasa es elinditasa custom topologia hasznalataval
    network = Mininet(topo= Topology(router_config, topology_config))
    network.start()

    # A routere interfeszeinek az IP cimeinek beallitasa
    configure_router_interfaces(network, router_config)

    # OSPF folyamat elinditasa minden routeren

    #for router in network.hosts:
    #    router.cmd(f'sudo python3 ospf.py {router.name} &')

    CLI(network)
    network.stop()