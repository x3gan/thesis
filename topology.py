from mininet.topo import Topo


class Topology(Topo):
    def __init__(self, router_config, topology_config):
        self.router_config = router_config
        self.topology_config = topology_config
        super().__init__()

    def build( self, *args, **params ):
        for router in self.router_config['router']:
            router_name = router
            self.addHost(router_name)

        for router, neighbours in self.topology_config['topology'].items():
            for neighbour in neighbours:
                self.addLink(router, neighbour)