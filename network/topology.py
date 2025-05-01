from typing import Any

from mininet.topo import Topo


class Topology(Topo):
    """Mininet topológia.

    A Topology osztály a Mininet hálózati topológiáját definiálja a konfigurációs fájl alapján.

    Attribútumok:
        config (dict): A konfigurációs fájl tartalmazza:
            - Routerek nevét, RID-ját, és area id-ját,
            - Interfészek nevét és IP-címét,
            - Az interfészeken található szomszédos routerek nevét.
    """
    def __init__(self, config: dict) -> None:
        self.config = config
        super().__init__()

    def build(self, *args: Any, **params : Any) -> None:
        """Felépíti a topológiát.

        A build metódus a Mininet hálózati topológiáját építi fel a konfigurációs fájl alapján.
        Létrhozza a hálózati eszközöket és hozzáadja akapcsolatokat.

        Megjegyzés:
            - A duplikált kapcsolatokat kiszűri a '_has_link' metódussal.
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
        """Ellenőrzi, hogy van-e már kétirányú kapcsolat két router között.

        Paraméterek:
            router (str): Egyik router neve.
            neighbour (str): Második router neve.

        Visszatérési érték:
            _ (bool): True, ha van már link a két router között, különben False.
        """
        for link in self.links():
            if router in link and neighbour in link:
                return True
        return False

