from .protocols import types, ethernet, arp, ip, icmp, udp, tcp, dns, raw
from . import packet
import socket, os

Ethernet = ethernet.Ethernet
ARP = arp.ARP
IP = ip.IP
ICMP = icmp.ICMP
UDP = udp.UDP
TCP = tcp.TCP
DNSQ = dns.DNSQ
DNSA = dns.DNSA
Raw = raw.Raw
Packet = packet.Packet

class Types:
    Proto_codes = types.ProtocolCode
    Layers = types.Layers

def bind_socket(sock, iface):
    try:
        sock.bind((iface, 0))
        return True
    except:
        return False

def send(packet:Packet, iface=None, sock=None):
    """
    Sends a packet per given or detected network interface
    """
    if not sock:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    interfaces = os.listdir('/sys/class/net/')
    is_bind = False
    if not iface:
        if Types.Layers.Ethernet in packet:
            for iface in interfaces:
                if iface != "lo":
                    is_bind = bind_socket(sock, iface)
                    if is_bind:
                        break
    else:
        is_bind = bind_socket(sock, iface)

    if not is_bind:
        raise Exception("Unable to bind socket")
    else:
        sock.send(packet.pack())
