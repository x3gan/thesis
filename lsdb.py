class LSDB:
    def __init__(self):
        self.lsdb = {}

    def add(self, key, value):
        """Add a key-value pair to the LSDB."""
        self.lsdb[key] = value

    def get(self, key):
        """Get a value by key from the LSDB."""
        return self.lsdb.get(key, None)

    def remove(self, key):
        """Remove a key-value pair from the LSDB."""
        if key in self.lsdb:
            del self.lsdb[key]