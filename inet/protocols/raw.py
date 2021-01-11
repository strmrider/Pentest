from .types import Layers

class Raw:
    """
    Raw data. Used as Packet's payload
    """
    def __init__(self, raw_data):
        self.data = raw_data
        self.type = Layers.RAW

    def pack(self):
        if type(self.data) == bytes:
            return self.data
        elif type(self.data) == int:
            return bytes(self.data)
        else:
            return self.data.encode()

    def __str__(self):
        return self.data

    def __len__(self):
        return len(self.data)