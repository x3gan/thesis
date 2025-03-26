from mininet.topo import Topo

# router.yml
# {'router':
#   {'R1':
#       {'interfaces':
#           {'R1-eth0': '10.0.0.1', 'R1-eth1': '10.0.0.2'},
#        'prefixlen': 24,
#        'ospf':
#           {'rid': None,
#           'areaid': '0.0.0.0'}
#    }, ...

# topology.yml
# {'topology':
#   {'R1': ['R2', 'R3'],
#    'R2': ['R4', 'R5']}
# }

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