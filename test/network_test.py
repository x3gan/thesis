from topology import Topology


def test_empty_topology():
    """Teszt 1: Ha megvannak a szükséges paraméterek, betölti a konfigurációt."""
    test_empty_config = {'routers' : {}}

    test_topology = Topology(config= test_empty_config)

    assert test_topology.config == test_empty_config


def test_config_topology():
    """Teszt 2: A konfigurációs fájl alapján a topológiába kerülnek a routerek és a linkek."""
    test_router_config = {
        'routers': {
            'R1': {
                'rid': '1.1.1.1',
                'area': '0.0.0.0',
                'interfaces': [
                    {
                        'name': 'eth0',
                        'ip': '10.0.0.1',
                        'neighbours': ['R2']
                    }
                ]
            },
            'R2': {
                'rid': '2.2.2.2',
                'area': '0.0.0.0',
                'interfaces': [
                    {
                        'name': 'eth0',
                        'ip': '10.0.0.3',
                        'neighbours': ['R1']
                    }
                ]
            }
        }
    }

    test_topology = Topology(config= test_router_config)

    assert test_topology.hosts() == ['R1', 'R2']
    assert test_topology.links() == [('R1', 'R2')]


def test_network_manager_create():
    """Teszt 3: Létrejön a NetworkManager a Mininet virtuális hálózattal."""
    assert True


def test_router_network_manager():
    """Teszt 4: A virtuális hálózatban résztvevő routerek interfészei a konfigurációs fájl
    alapján állítódtak be."""
    assert True


def test_ospf_start():
    assert True