import struct, binascii, socket
from .types import Layers

def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

PACK_FORMAT = "! 2H 2B H 6s 4s 6s 4s"

class ARP:
    """
    ARP protocol network packet
    """
    def __init__(self, src_mac="", src_ip="", dest_mac="", dest_ip=""):
        self.type = Layers.ARP
        # Default values are set for ethernet and IPV4
        self.htype = 1 # Hardware type
        self.ptype = 0x0800 # Protocol type
        self.hlen = 6 # Hardware address length
        self.plen = 4 # Protocol address length
        self.opcode = 2
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.dest_mac = dest_mac
        self.dest_ip = dest_ip

    def dissect(self, data):
        unpacked_data = struct.unpack(PACK_FORMAT, data)
        self.htype = unpacked_data[0]
        self.ptype = unpacked_data[1]
        self.hlen = unpacked_data[2]
        self.plen = unpacked_data[3]
        self.opcode = unpacked_data[4]
        self.src_mac = get_mac_addr(unpacked_data[5])
        self.src_ip = socket.inet_ntoa(unpacked_data[6])
        self.dest_mac = get_mac_addr(unpacked_data[7])
        self.dest_ip = socket.inet_ntoa(unpacked_data[8])

    def pack(self):
        src_mac = binascii.unhexlify(self.src_mac.replace(':', '').replace('-', ''))
        dest_mac = binascii.unhexlify(self.dest_mac.replace(':', '').replace('-', ''))
        return struct.pack(PACK_FORMAT, self.htype, self.ptype, self.hlen, self.plen, self.opcode,
                           src_mac, socket.inet_aton(self.src_ip), dest_mac, socket.inet_aton(self.dest_ip))

    def __str__(self):
        return "===ARP====\n"\
               "Hardware address length: {}\n" \
               "Protocol address length: {}\n" \
               "Source - MAC: {} IP: {}\n" \
               "Destination - MAC: {} IP: {}\n" \
               "Operation: {}".format(self.hlen, self.plen, self.src_mac, self.src_ip,
                                      self.dest_mac, self.dest_ip, self.opcode)

    def summary(self):
        return "===ARP====\n" \
               "Source - MAC: {} IP: {}\n" \
               "Destination - MAC: {} IP: {}\n" \
               "Operation: {}".format(self.src_mac, self.src_ip, self.dest_mac, self.dest_ip, self.opcode)