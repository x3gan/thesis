from mininet.topo import Topo


class Topology(Topo):
    def __init__(self):
        super().__init__()

        r1 = self.addHost('R1')
        r2 = self.addHost('R2')
        r3 = self.addHost('R3')

        self.addLink(r1, r2)
        self.addLink(r1, r3)