from scapy.packet import Packet


class LSDB:
    """OSPF kapcsolat-állapot adatbázis.

    Az LSDB (link-state databse) osztály implementálja az OSPF protokoll kapcsolat-állapot
    adatbázist. Az LSA-k tárolásáért felelős, tárolja a router által ismert topológiai
    információkat.

    Paraméterek:
        _lsa_db (dict): A szótár az LSA-kat tárolja LSA típus és a szomszéd RID-ja alapján.
    """
    def __init__(self) -> None:
        self.lsa_db : dict[int, dict[str, Packet]] = {}

    def add(self, lsa: Packet) -> None:
        """Új LSA-k hozzáadása az adatbázishoz.

        Paraméterek:
            lsa (Packet): OSPF LSA csomag (OSPF_LSA_Hdr-t tartalmaz)

        Megjegyzés:
            - Mindig csak a legújabb verziójú (szekvenciaszámú) LSA-kat tárolja.
        """
        lsa_type = lsa.type
        lsa_adrouter = lsa.adrouter

        key = lsa_adrouter

        if lsa_type not in self.lsa_db:
            self.lsa_db[lsa_type] = {}

        self.lsa_db[lsa_type][key] = lsa

    def get(self, adrouter: str, lsa_type: int) -> Packet | None:
        """LSA lekérdezése az adatbázisból.

        LSA típus és RID szerint lekérdezi az LSA-t.

        Paraméterek:
            adrouter (str): Az LSA-t küldő router RID-ja.
            lsa_type (int): Az LSA típusa (pl. 1 = Router_LSA)

        Visszatérési értek:
            lsa (Packet | None): Az LSA csomag.
        """
        if lsa_type not in self.lsa_db:
            self.lsa_db[lsa_type] = {}

        lsa = self.lsa_db[lsa_type].get(adrouter, None)
        return lsa

    def get_all(self) -> list[Packet]:
        """Visszaadja az összes LSA csomagot az adatbázisból.

        Visszatérési érték:
            packets (list): Az összes LSA csomag listája

        TODO: típus szerint
        """
        packets = []

        for type in self.lsa_db.values():
            for packet in type.values():
                packets.append(packet)

        return packets