class LSDB:
    def __init__(self):
        self.lsa_list = {}

    def add(self, router_id, lsa):
        self.lsa_list[router_id] = lsa

    def get(self, router_id):
        return self.lsa_list.get(router_id, None)

