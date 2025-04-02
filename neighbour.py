class Neighbour:
    def __init__(self):
        self.rid = None
        self.ip = None
        self.mac = None
        self.is_master = None
        self.last_seen = None
        self.state = 'DOWN'

    def build(self, rid = None, ip = None, mac = None, is_master = None, last_seen = None, state = 'DOWN'):
        if rid is not None:
            self.rid = rid
        if ip is not None:
            self.ip = ip
        if mac is not None:
            self.mac = mac
        if is_master is not None:
            self.is_master = is_master
        if last_seen is not None:
            self.last_seen = last_seen
        if state is not None:
            self.state = state

        return self


def display(self):
    """Return a string representation of the neighbour."""
    return f"{self.ip} - {self.mac} - {self.is_master} - {self.last_seen} - {self.state}"