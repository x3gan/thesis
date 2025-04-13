from typing import Dict

from scapy.contrib.ospf import OSPF_LSA_Hdr, OSPF_Router_LSA
from scapy.packet import Packet


class LSDB:
    def __init__(self):
        self.lsa_db : dict[int, dict[tuple, Packet]] = {}

    def add(self, lsa: Packet) -> None:
        """
        LSA hozzáadása az adatbázishoz (csak a legfrissebb verziót tároljuk)
        :param lsa: OSPF LSA csomag (OSPF_LSA_Hdr-t tartalmazó)
        """
        lsa_hdr  = lsa[OSPF_LSA_Hdr]
        lsa_type = lsa_hdr.type
        key      = (lsa_hdr.id, lsa_hdr.adrouter)

        if lsa_type not in self.lsa_db:
            self.lsa_db[lsa_type] = {}

        self.lsa_db[lsa_type][key] = lsa

    def get(self, adrouter):
        return self.lsa_db.get(adrouter, None)

    def get_all(self) -> list[Packet]:
        return [lsa for lsa_type in self.lsa_db.values() for lsa in lsa_type.values()]
