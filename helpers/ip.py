dscp_classes = {
    0: "Default",
    10: "AF11",
    12: "AF12",
    16: "CS2",
    46: "EF",
    32: "CS4",
    48: "CS6" 
}

ecn_map = {
    0: "Not ECN-Capable Transport",
    1: "ECN Capable Transport (ECT(1))",
    2: "ECN Capable Transport (ECT(0))",
    3: "Congestion Experienced (CE)"
}

flags_map = {
    0x0: "No flags set (0x0)", 
    0x1: "DF (Don't Fragment; 0x1)",
    0x2: "MF (More Fragments; 0x2)"
}

proto_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

proto_map_6 = {
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
    0: "Hop-by-Hop Options",
    43: "Routing Header",
    44: "Fragment Header",
    60: "Destination Options",
    51: "Authentication Header",
    50 : "Encapsulating Security Payload (ESP)"
}