from state import State


class Neighbour:
    def __init__(self):
        self.rid = None
        self.ip = None
        self.mac = None
        self.last_seen = None
        self.state = 'DOWN'

    def build(self, rid = None, ip = None, mac = None, last_seen = None, state = State.DOWN):
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

    def display(self):
        return f"{self.rid} - {self.ip} - {self.mac} - {self.last_seen} - {self.state}"