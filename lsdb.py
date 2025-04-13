from scapy.contrib.ospf import OSPF_LSA_Hdr, OSPF_Router_LSA


class LSDB:
    def __init__(self):
        self.lsa_list = {}

    def add(self, lsa):
        if not lsa.haslayer(OSPF_Router_LSA):
            return

        body = lsa.getlayer(OSPF_Router_LSA)

        self.lsa_list[body.adrouter] = lsa

    def get(self, adrouter):
        return self.lsa_list.get(adrouter, None)

    def get_all(self):
        return list(self.lsa_list.values())