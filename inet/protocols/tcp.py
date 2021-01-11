import struct, socket
from .types import Layers

PACK_FORMAT = '!2H 2I 4H'

class TcpFlags:
    def __init__(self):
        self.ns = 0
        self.cwr = 0
        self.ece = 0
        self.urg = 0
        self.ack = 0
        self.psh = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0

    def dissect(self, flags):
        self.ns = flags & 0b100000000
        self.cwr = flags & 0b010000000
        self.ece = flags & 0b001000000
        self.urg = flags & 0b000100000
        self.ack = flags & 0b000010000
        self.psh = flags & 0b000001000
        self.rst = flags & 0b000000100
        self.syn = flags & 0b000000010
        self.fin = flags & 0b000000001

    def pack(self):
        ns = self.ns << 8
        cwr = ns | (self.cwr << 7)
        ece = cwr | (self.ece << 6)
        urg = ece | (self.urg << 5)
        ack = urg | (self.ack << 4)
        psh = ack | (self.psh << 3)
        rst = psh | (self.rst << 2)
        syn = rst | (self.syn << 1)

        return syn | self.fin


    def __str__(self):
        return "====Flags====\n" \
               "URG: {}\n" \
               "ACK: {}\n" \
               "PSH: {}\n" \
               "RST: {}\n" \
               "SYN: {}\n" \
               "FIN: {}\n".format(self.urg, self.ack, self.psh, self.rst, self.syn, self.fin)

class TCP:
    """
    TCP network packet
    """
    def __init__(self, src_port=0, dest_port=0, sequence=0, ack=0, syn=0, fin=0):
        self.type = Layers.TCP
        self.src_port = src_port
        self.dest_port = dest_port
        # sequence number
        self.sqe_number = sequence
        # Acknowledgment number
        self.ack_number = 0
        self.data_offset = 5
        self.reserved = 0
        self.flags = TcpFlags()
        self.flags.ack = ack
        self.flags.syn = syn
        self.flags.fin = fin
        self.window_size = socket.htons (5840)
        self.checksum = 0
        # urgent pointer
        self.urg_pointer = 0

    def dissect(self, data):
        header = struct.unpack(PACK_FORMAT, data[:20])
        self.src_port = header[0]
        self.dest_port = header[1]
        # sequence number
        self.sqe_number = header[2]
        # Acknowledgment number
        self.ack_number = header[3]
        self.data_offset = header[4] >> 12
        self.reserved = (header[4] >> 6) * 4
        flags = (header[4] << 7) >> 7
        self.flags = TcpFlags()
        self.flags.dissect(flags)
        self.window_size = header[5]
        self.checksum = header[6]
        # urgent pointer
        self.urg_pointer = header[7]

    def pack(self):
        offset_and_flags = (self.data_offset << 12) | (self.reserved << 9) | self.flags.pack()
        return struct.pack(PACK_FORMAT, self.src_port, self.dest_port, self.sqe_number, self.ack_number,
                           offset_and_flags, self.window_size, self.checksum, self.urg_pointer)

    def __str__(self):
        return "====TCP Header====\n" \
               "Source port: {}\n" \
               "Destination port: {}\n" \
               "Sequence number: {}\n" \
               "Acknowledgment number: {}\n" \
               "Data offset: {}\n" \
               "Reserved: {}\n" \
               "Window size: {}\n" \
               "Checksum: {}\n" \
               "Urgent pointer: {}\n".format(self.src_port, self.dest_port, self.sqe_number, self.ack_number,
                                             self.data_offset, self.reserved, self.window_size, self.checksum,
                                             self.urg_pointer) + self.flags.__str__()

    def summary(self):
        return "Protocol: TCP Source port: {} Destination port: {}".format(self.src_port, self.dest_port)

