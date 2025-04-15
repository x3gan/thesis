from mininet.topo import Topo


class Topology(Topo):
    def __init__(self, config : dict) -> None:
        self.config = config
        super().__init__()

    def build( self, *args, **params ) -> None:
        for router in self.config['routers']:
            router_name = router
            self.addHost(router_name)

        for router, info in self.config['routers'].items():
            for interface in self.config['routers'][router]['interfaces']:
                for neighbour in interface['neighbours']:
                    if not self.has_link(router, neighbour):
                        self.addLink(router, neighbour)

    def has_link(self, router : str, neighbour : str) -> bool:
        for link in self.links():
            if router in link and neighbour in link:
                return True
        return False

