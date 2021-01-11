import struct, socket
from .types import Layers

UNDEFINED_IP = "0.0.0.0"
PACK_FORMAT = '!2B 3H 2B H 4s 4s'

class IpV4Flags:
    def __init__(self):
        self.reserved = 0
        # don't fragment flag
        self.df = 1
        # more fragment flag
        self.mf = 0

    def dissect(self, flags):
        self.reserved = 0
        self.df = flags >> 1
        self.mf = flags & 0x1

    def pack(self):
        reserved = self.reserved << 7
        df = (reserved | self.df) << 6
        return (df | self.mf) << 5

class IP:
    """
    IPV4 network packet
    """
    def __init__(self, version=4, length=20, ttl=255, protocol=144, src_ip=UNDEFINED_IP, dest_ip=UNDEFINED_IP):
        self.type = Layers.IP
        self.version = version
        # internet Header Length (minimum is 5, max i 15)
        self.ihl = 5
        # type of service
        self.tos = 0
        # minimum size is 20
        self.total_length = length
        # identification
        self.id = 1#0x3a57
        self.flags = IpV4Flags()
        # fragment offset (minimum is 65528)
        self.offset = 65528
        # time to live
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = 0
        self.src_ip = src_ip
        self.dest_ip = dest_ip

    def add_payload_length(self, length):
        self.total_length = 20 + length

    def dissect(self, data):
        header = struct.unpack(PACK_FORMAT, data[:20])
        self.version = header[0] >> 4
        self.ihl = (header[0] & 15) * 4
        self.tos = header[1] >> 2
        self.total_length = header[2]
        self.id = header[3]
        self.flags = IpV4Flags()
        self.flags.dissect(header[4] >> 13)
        self.offset = header[4] & 0x1fff
        self.ttl = header[5]
        self.protocol = header[6]
        self.checksum = header[7]
        self.src_ip = socket.inet_ntoa(header[8])
        self.dest_ip = socket.inet_ntoa(header[9])

    def pack(self):
        version_ihl = self.ihl | (self.version << 4)
        tos = 0 | (self.tos << 2)
        flags_and_offset = 0
        src_ip = socket.inet_aton(self.src_ip)
        dest_ip = socket.inet_aton(self.dest_ip)
        pack = struct.pack(PACK_FORMAT, version_ihl, tos, self.total_length, self.id, flags_and_offset, self.ttl,
                           self.protocol, self.checksum, src_ip, dest_ip)

        return bytearray(pack)

    def __str__(self):
        return "====IP Header====\n" \
                "Version: {}\n"\
                "IHL: {}\n"\
                "TOS: {}\n" \
                "Total length: {}\n" \
                "Identification: {}\n" \
                "Time to Live: {}\n" \
                "Protocol: {}\n" \
                "Checksum: {}\n" \
                "source ip: {}\n" \
                "Destination ip: {}\n".format(self.version, self.ihl, self.tos, self.total_length, self.id, self.ttl,
                                            self.protocol, self.checksum, self.src_ip, self.dest_ip)

    def summary(self):
        return "Version: {} TTL: {} Protocol: {} source IP: {} Destination IP: {}".format(self.version, self.ttl,
                                                                                          self.protocol,
                                                                                          self.src_ip,
                                                                                          self.dest_ip)

