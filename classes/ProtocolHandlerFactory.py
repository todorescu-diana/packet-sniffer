from classes.l2.ARPHandler import ARPHandler 
from classes.l2.EthernetHandler import EthernetHandler
from classes.l3.IPHandler import IPHandler
from classes.l3.ICMPHandler import ICMPHandler
from classes.l4.TCPHandler import TCPHandler 
from classes.l4.UDPHandler import UDPHandler
from classes.l7.DNSHandler import DNSHandler
from helpers.gen_const import protocol_map, encapsulating_protocol_map

class ProtocolHandlerFactory:
    @staticmethod
    def create_handler(protocol, verbose=True, log=False):
        encapsulating_layers = ProtocolHandlerFactory.create_encapsulating_layers(protocol, verbose, log)

        if protocol_map[protocol] == "TCP":
            return TCPHandler(encapsulating_layers, verbose, log)
        elif protocol_map[protocol] == "UDP":
            return UDPHandler(encapsulating_layers,verbose, log)
        elif protocol_map[protocol] == "ICMP":
            return ICMPHandler(encapsulating_layers,verbose, log)
        elif protocol_map[protocol] == "ARP":
            return ARPHandler(encapsulating_layers,verbose, log)
        elif protocol_map[protocol] == "DNS":
            return DNSHandler(encapsulating_layers,verbose, log)
        elif protocol_map[protocol] == "Ether":
            return EthernetHandler(encapsulating_layers,verbose, log)
        elif protocol_map[protocol] == "IP":
            return IPHandler(encapsulating_layers,verbose, log)
        else:
            raise ValueError(f"Unknown protocol: {protocol}")
        
    @staticmethod
    def create_encapsulating_layers(protocol, verbose, log):
        encapsulating_layers = {}
        encapsulating_protocols = encapsulating_protocol_map.get(protocol, [])
        for pr in encapsulating_protocols:
            encapsulating_layers[protocol_map[pr]] = ProtocolHandlerFactory.create_handler(pr, verbose, log)

        return encapsulating_layers