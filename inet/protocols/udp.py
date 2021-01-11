import struct
from .types import Layers

PACK_FORMAT = "!4H"
class UDP:
    """
    UDP network packet
    """
    def __init__(self, src_port=0, dest_port=0, length=8):
        self.type = Layers.UDP
        self.src_port = src_port
        self.dest_port = dest_port
        self.length = length
        self.checksum = 0

    def add_length(self, length):
        """
        Sets length property. includes default 8 bytes and payload
        """
        self.length = 8 + length

    def dissect(self, data):
        header = struct.unpack(PACK_FORMAT, data[:8])
        self.src_port = header[0]
        self.dest_port = header[1]
        self.length = header[2]
        self.checksum = header[3]

    def pack(self):
        return struct.pack(PACK_FORMAT, self.src_port, self.dest_port, self.length, self.checksum)

    def __str__(self):
        return "====UDP Header====\n"\
                "Source port: {}\n"\
                "Destination port: {}\n"\
                "Length: {}\n"\
                "Checksum: {}\n".format(self.src_port, self.dest_port, self.length, self.checksum)

    def summary(self):
        return "Source port: {} Destination port: {}".format(self.src_port, self.dest_port)