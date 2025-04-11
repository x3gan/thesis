from scapy.contrib.ospf import OSPF_LSA_Hdr


class LSDB:
    def __init__(self):
        self.lsa_list = {}

    def add(self, lsa):
        if not lsa.haslayer(OSPF_LSA_Hdr):
            return

        hdr = lsa.getlayer(OSPF_LSA_Hdr)
        key = (hdr.adrouter, hdr.id)

        self.lsa_list[key] = lsa

    def get(self, adrouter, lsa_id):
        return self.lsa_list.get((adrouter, lsa_id), None)

    def get_all(self):
        return list(self.lsa_list.values())