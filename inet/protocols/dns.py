import struct, socket
from .types import Layers

def get_dns_qr(data):
    qr = struct.unpack("!2x H", data)[0]
    return qr >> 15

class DNSFlags:
    def __init__(self):
        self.aa = 0
        self.tc = 0
        self.rd = 0
        self.ra = 0
        self.z = 0
        self.ad = 0
        self.cd = 0

    def dissect(self, data):
        pass

    def pack(self):
        aa = (self.aa | 0x00) << 6
        tc = aa | (self.tc << 5)
        rd = tc | (self.rd << 4)
        ra = rd | (self.ra << 3)
        z = ra | (self.z << 2)
        ad = z | (self.ad << 1)
        cd = ad | self.ad
        return cd

    def __str__(self):
        return "aa: {}, tc: {}, rd: {}, ra: {}, z: {}, ad: {}, cd: {}".format(self.aa, self.tc, self.rd, self.ra,
                                                                              self.z, self.ad, self.cd)

class DNS:
    def __init__(self):
        self.type = Layers.DNS
        self.id = 1
        self.qr = 0
        self.opcode = 0
        self.flags = DNSFlags()
        self.rcode = 0
        self.questions = 1
        self.answers = 0
        self.authority = 0
        self.additional = 0
        self.data = ""

    def dissect(self, data):
        header = struct.unpack("!6H", data)
        self.id = header[0]
        self.qr = header[1] >> 15
        self.opcode = ((header[1] >> 11) << 12) >> 12
        flags_data = ((header[1] >> 4) << 9) >> 9
        self.flags = DNSFlags()
        self.flags.dissect(flags_data)
        self.rcode = (header[1] << 12) >> 12
        self.questions = header[2]
        self.answers = header[3]
        self.authority = header[4]
        self.additional = header[5]
        self.data = data[12:]

    def pack(self):
        qr = (self.qr | 0x00) << 15
        qr_opcode = qr | (self.opcode << 11)
        flags_rcode = ( self.flags.pack() << 4) | self.rcode
        return struct.pack("!6H", self.id, (qr_opcode | flags_rcode), self.questions,
                           self.answers,self.authority, self.additional)

    @staticmethod
    def get_name_offset(data):
        for i, byte in enumerate(data):
            if byte == 0x00:
                return i

    @staticmethod
    def pack_name(name, add_end=True):
        labels = name.split('.')
        data = bytes()
        for label in labels:
            data += len(label).to_bytes(1, "big") + bytes(label.encode())

        if add_end:
            final = 0
            data += final.to_bytes(1, "big")

        return data

    def __str__(self):
        return "====DNS====\n" \
               "ID: {}\n" \
               "QR: {}, Operation: {}, Rcode: {}\n" \
               "Flags: {}\n" \
               "Questions: {}, Answers: {}, Authority: {}, Additional: {}".format(self.id, self.qr, self.opcode,
                                                                                  self.rcode, self.flags.__str__(),
                                                                                  self.questions, self.answers,
                                                                                  self.authority, self.additional)

class DNSQ(DNS):
    """
    DNS Query
    """
    def __init__(self, name=""):
        DNS.__init__(self)
        self.name = name
        self.qtype = 0x0001
        self.qclass = 0x0001

        self.qr = 0
        self.flags.rd = 1

    def parse(self, data):
        super().dissect(data)
        offset = self.get_name_offset(self.data)
        self.name = self.data[:offset]
        self.qtype, self.qclass = struct.unpack("!HH", self.data[:offset+1].encode())

    def pack(self):
        return super().pack() + self.short_pack()

    def short_pack(self):
        pack = struct.pack("!2H", self.qtype, self.qclass)
        return self.pack_name(self.name) + pack

    def __str__(self):
        return super().__str__() + "\n" + "Name: {}\n Type: {} Class: {}".format(self.name, self.qtype, self.qclass)

class DNSA(DNS):
    """
    DNS Answer
    """
    def __init__(self, name="", ttl=255, rdata=""):
        DNS.__init__(self)
        self.name= name
        self.type = 0x0001
        self.aclass = 0x0001
        self.ttl = ttl
        self.rdata = rdata
        self.rd_length = len(rdata)

        # DNS header values
        self.qr = 1
        self.flags.rd = 1
        self.flags.ra = 1
        self.questions = 1
        self.answers = 1

    def parse(self, data):
        super().dissect(data)
        offset = self.get_name_offset(self.data)
        self.name = self.data[:offset+1]
        self.data = self.data[:offset+2]
        self.rd_length = struct.unpack("!8x H", self.data)
        self.type, self.aclass, self.ttl, self.rdata = struct.unpack("!H H I 2x {}s".format(self.rd_length), self.data)

    def pack(self):
        if self.type == 0x0001:
            self.rd_length = 4
        pack = struct.pack("!H H H I H 4s", 0xC00C, self.type, self.aclass, self.ttl, self.rd_length,
                           socket.inet_aton(self.rdata))
        query = DNSQ()
        query.name = self.name
        return super().pack() + query.short_pack() + pack

    def __str__(self):
        return super().__str__() + "\n" + "Name: {}\n Type: {} Class: {}\n" \
                                          "Time Ti Live: {}\n" \
                                          "RData: {}".format(self.name, self.type, self.aclass, self.ttl, self.rdata)