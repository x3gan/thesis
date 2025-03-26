from mininet.cli import CLI
from mininet.net import Mininet
from topology import Topology

if __name__ == '__main__':
    net = Mininet(topo=Topology())
    net.start()

    r1 = net.get('R1')
    #print(type(r1)) # <class 'mininet.node.Host'>
    r2 = net.get('R2')
    r3 = net.get('R3')

    r1.setIP(
        ip='10.0.0.1',
        prefixLen=24,
        intf='R1-eth0'
    )

    r1.setIP(
        ip='10.0.0.2',
        prefixLen=24,
        intf='R1-eth1'
    )

    r2.setIP(
        ip='10.0.0.3',
        prefixLen=24,
        intf='R2-eth0'
    )

    r3.setIP(
        ip='10.0.0.4',
        prefixLen=24,
        intf='R3-eth0'
    )

    print(r1.MAC())

    # r1.cmd('')
    # r2.cmd('')
    # r3.cmd('')

    # elvileg van alapbol
    # mininet > R1 sysctl net.ipv4.ip_forward
    # net.ipv4.ip_forward = 1
    # mininet > R3 sysctl net.ipv4.ip_forward
    # net.ipv4.ip_forward = 1
    # mininet > R2 sysctl net.ipv4.ip_forward
    # net.ipv4.ip_forward = 1
    a = r1.cmd('sudo python3 ospf.py 2')
    print(a)

    CLI(net)
    net.stop()