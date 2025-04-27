from datetime import datetime

from ospf_core.state import State


class Neighbour:
    """Egy OSPF szomszédos router állapotát és adatait tárolja.

    A szomszédos routerekről tárol a hálózati csomagok alapján megszerzett információkat.

    Attribútumok:
        rid (str): Router ID (a router egyedi azonosítója).
        ip (str): A szomszéd  IP címe.
        mac (str): A szomszéd MAC címe.
        last_seen (datetime): A szomszédtól kapott utolsó Hello csomag érkezésének időpontja.
        state (State): A szomszéd aktuális OSPF állapota.
    """
    def __init__(self) -> None:
        self.rid = None
        self.ip = None
        self.mac = None
        self.last_seen = None
        self.state = State.DOWN

    def build(self, rid: str = None, ip: str = None, mac: str = None, last_seen: datetime = None,
              state: State = State.DOWN) -> 'Neighbour':
        """Inicializálja a szomszéd adatait.

        A már létrehozott szomszédnak az értékeit módosítja vagy beállítja.

        Paraméterek:
            rid, ip, mac, last_seen, state: Lásd attribútumok.

        Visszatérési érték:
            self (Neighbour): Az adatokkal frissített szomszéd példány.
        """
        if rid is not None:
            self.rid = rid
        if ip is not None:
            self.ip = ip
        if mac is not None:
            self.mac = mac
        if last_seen is not None:
            self.last_seen = last_seen
        if state is not None:
            self.state = state

        return self