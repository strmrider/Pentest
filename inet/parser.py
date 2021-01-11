from .protocols import types, ethernet, ip, arp, icmp, tcp, udp, dns, raw

def parse_udp(raw_data, layers_list):
    layer = udp.UDP()
    layer.dissect(raw_data)
    layers_list.append(layer)
    if layer.dest_port == 52:
        dns_qr = dns.get_dns_qr(raw_data[8:])
        if dns_qr == 0:
            layer = dns.DNSQ()
            layer.parse(raw_data[8:])
        else:
            layer = dns.DNSA()
            layer.parse(raw_data[8:])
            layers_list.append(layer)

def parse_ipv4(raw_data, layers_list):
    iplayer = ip.IP()
    iplayer.dissect(raw_data)
    layers_list.append(iplayer)
    if iplayer.protocol == types.ProtocolCode.ICMP:
        layer = icmp.ICMP()
        layer.dissect(raw_data[iplayer.ihl:])
    elif iplayer.protocol == types.ProtocolCode.TCP:
        layer = tcp.TCP()
        layer.dissect(raw_data[iplayer.ihl:])
        payload = raw.Raw(raw_data[layer.data_offset])
        layers_list.append(payload)
    elif iplayer.protocol == types.ProtocolCode.UDP:
        parse_udp(raw_data[iplayer.ihl:], layers_list)

def parse(raw_data, wlan=False):
    layers_list = []
    eth = ethernet.Ethernet()
    eth.dissect(raw_data)
    layers_list.append(eth)
    if eth.protocol == types.ProtocolCode.IPv4:
        parse_ipv4(raw_data[14:], layers_list)
    elif eth.protocol == types.ProtocolCode.ARP:
        arp_layer = arp.ARP()
        arp_layer.dissect(raw_data[14:14+28])
        layers_list.append(arp_layer)

    return layers_list