protocol_map = {
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
    "arp" : "ARP",
    "dns": "DNS",
    "ether": "Ether",
    "ip": "IP"
}

encapsulating_protocol_map = {
    "arp": ["ether"],
    "icmp": ["ip", "ether"],
    "ip": ["ether"],
    "tcp": ["ip", "ether"],
    "udp": ["ip", "ether"],
    "dns" : ["udp", "ip", "ether"]
}

valid_modes = ["only-log", "log-live", "live"]
valid_protocols = ["arp", "icmp", "tcp", "udp", "dns"]