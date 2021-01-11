import struct, binascii, random
from .types import Layers

IPV4 = 0x0800
PACK_FORMAT = '!6s6sH'

def get_mac_addr(mac_raw):
    """
    converts MAC address in bytes to string format
    """
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

def generate_mac_addr():
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                 random.randint(0, 255),
                                 random.randint(0, 255))

class Ethernet:
    """
    Ethernet network packet
    """
    def __init__(self, src_mac=None, dest_mac=None, protocol = IPV4):
        self.type = Layers.Ethernet
        self.dest_mac = dest_mac if dest_mac else generate_mac_addr()
        self.src_mac = src_mac if src_mac else generate_mac_addr()
        self.protocol = protocol # IpV4

    def dissect(self, data):
        header = struct.unpack(PACK_FORMAT, data[:14])
        self.dest_mac = get_mac_addr(header[0])
        self.src_mac = get_mac_addr(header[1])
        self.protocol = header[2]

    def pack(self):
        dest_mac = binascii.unhexlify(self.dest_mac.replace(':', '').replace('-', ''))
        src_mac = binascii.unhexlify(self.src_mac.replace(':', '').replace('-', ''))
        return struct.pack(PACK_FORMAT, dest_mac, src_mac, self.protocol)

    def __str__(self):
        return "====Ethernet====\n" \
               "Destination MAC: {}\n" \
               "source MAC: {}\n" \
               "protocol version: {}\n".format(self.dest_mac, self.src_mac, self.protocol)

    def summary(self):
        return "Destination MAC: {} source MAC: {}".format(self.dest_mac, self.src_mac)