from typing import Dict

from scapy.contrib.ospf import OSPF_LSA_Hdr, OSPF_Router_LSA
from scapy.packet import Packet


class LSDB:
    def __init__(self) -> None:
        self.lsa_db : dict[int, dict[str, Packet]] = {}

    def add(self, lsa: Packet) -> None:
        """
        LSA hozzáadása az adatbázishoz (csak a legfrissebb verziót tároljuk)
        :param lsa: OSPF LSA csomag (OSPF_LSA_Hdr-t tartalmazó)
        """
        lsa_type = lsa.type
        lsa_adrouter = lsa.adrouter

        key = lsa_adrouter

        if lsa_type not in self.lsa_db:
            self.lsa_db[lsa_type] = {}

        self.lsa_db[lsa_type][key] = lsa

    def get(self, adrouter : str, lsa_type : int) -> Packet | None:
        """
        LSA lekérdezése az adatbázisból.
        :param ad_id: A LSA
        :param adrouter:
        :param lsa_type:
        :return:
        """
        if lsa_type not in self.lsa_db:
            self.lsa_db[lsa_type] = {}

        lsa = self.lsa_db[lsa_type].get(adrouter, None)
        return lsa

    def get_all(self) -> list[Packet]:
        """
        Visszaadja az összes LSA csomagot az adatbázisból.
        :return: Az összes LSA csomag listája
        """
        packets = []

        for type in self.lsa_db.values():
            for packet in type.values():
                packets.append(packet)

        return packets