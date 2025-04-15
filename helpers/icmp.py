icmp_types = {
    (8, 0): "Echo Request",
    (0, 0): "Echo Reply",
    (3, 0): "Destination Unreachable - Network Unreachable",
    (3, 1): "Destination Unreachable - Host Unreachable",
    (3, 2): "Destination Unreachable - Protocol Unreachable",
    (3, 3): "Destination Unreachable - Port Unreachable",
    (11, 0): "TTL Expired - Time Exceeded",
    (11, 1): "TTL Expired - Fragment Reassembly Time Exceeded",
}