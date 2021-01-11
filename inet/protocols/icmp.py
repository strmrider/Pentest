import struct
from .types import Layers

PACK_FORMAT = '!B B H H H 4s'

class ICMP:
    """
    ICMP (Internet Control Message Protocol) network packet
    """
    def __init__(self, type=0, code=0, checksum=0, id=1, sequence=1, data=""):
        self.type = Layers.ICMP
        self.htype = type
        self.code = code
        self.checksum = checksum
        self.id = id
        self.seq_number = sequence
        self.data = data

    def dissect(self, data):
        self.htype, self.code, self.checksum, self.id, self.seq_number, self.data = struct.unpack(PACK_FORMAT, data[:12])

    def pack(self):
        return struct.pack(PACK_FORMAT, self.htype, self.code, self.checksum,
                           self.id, self.seq_number, self.data.encode())

    def __str__(self):
        return "===ICMP===\n" \
               "Type: {}\n"\
               "Code: {}\n"\
               "Checksum: {}\n".format(self.htype, self.code, self.checksum)

    def summary(self):
        return self.__str__()