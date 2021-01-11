##########
# Layers
##########
class Layers:
    Ethernet = 0
    ARP = 1
    IP = 2
    ICMP = 3
    TCP = 4
    UDP = 5
    DNS = 6
    RAW = 7

    @staticmethod
    def get_name(layer):
        if layer == 0:
            return "Ethernet"
        elif layer == 1:
            return "ARP"
        elif layer == 2:
            return "IPV4"
        elif layer == 3:
            return "ICMP"
        elif layer == 4:
            return "TCP"
        elif layer == 5:
            return "UDP"
        elif layer == 6:
            return "DNS"
        elif layer == 7:
            return "RAW"

##################
# Protocols codes
##################
class ProtocolCode:
    IPv4 = 0x0800
    ARP = 0x0806
    ICMP = 0x01
    TCP = 0x06
    UDP = 0x11