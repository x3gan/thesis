from typing import Any


from mininet.topo import Topo


class Topology(Topo):
    """
    A Topology osztály a Mininet hálózati topológiáját definiálja a konfigurációs fájl alapján.

    Attribútumok:
    config (dict): A konfigurációs fájl tartalma, amely tartalmazza a routerek és azok interfészeinek adatait.
    """
    def __init__(self, config : dict) -> None:
        self.config = config
        super().__init__()

    def build(self, *args : Any, **params : Any) -> None:
        """
        A build metódus a Mininet hálózati topológiáját építi fel a konfigurációs fájl alapján.
        A metódus létrehozza a routereket és a közöttük lévő linkeket.

        Paraméterek:
        *args: További argumentumok.
        **params: További paraméterek.
        """
        if self.config['routers']:
            for router in self.config['routers']:
                router_name = router
                self.addHost(router_name)

            for router, info in self.config['routers'].items():
                for interface in self.config['routers'][router]['interfaces']:
                    for neighbour in interface['neighbours']:
                        if not self._has_link(router, neighbour):
                            self.addLink(router, neighbour)

    def _has_link(self, router : str, neighbour : str) -> bool:
        """
        Ellenőrzi, hogy van-e már link a két router között.

        Parameterek:
        router (str): Az első router neve.
        neighbour (str): A második router neve.

        Visszatérési érték:
        bool: True, ha van már link a két router között, különben False.
        """
        for link in self.links():
            if router in link and neighbour in link:
                return True
        return False

