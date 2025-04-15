from classes.ProtocolHandlerFactory import ProtocolHandlerFactory

protocol_handlers = {}

def packet_callback(packet, protocol, verbose=True, log=False):
    if protocol not in protocol_handlers.keys():
        handler = ProtocolHandlerFactory.create_handler(protocol, verbose, log)
        protocol_handlers[protocol] = handler
        protocol_handlers.get(protocol).handle_packet(packet)
    else:
        protocol_handlers.get(protocol).handle_packet(packet)