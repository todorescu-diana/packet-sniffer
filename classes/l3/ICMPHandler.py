from datetime import datetime as dt
import logging
import click
from classes.ProtocolHandler import ProtocolHandler
from scapy.all import *
from helpers.icmp import *

logger = logging.getLogger(__name__)

class ICMPHandler(ProtocolHandler):
    def handle_packet(self, packet, idt=""):
        if packet.haslayer('ICMP'):
            timestamp = packet.time
            time = dt.fromtimestamp(timestamp)
            receive_time = time.strftime("%d-%m-%Y %H:%M:%S")

            ICMP_layer = packet["ICMP"]

            packet_type = ICMP_layer.type
            packet_code = ICMP_layer.code

            pkt_type = self.get_icmp_type(packet_type, packet_code)

            payload_len = len(ICMP_layer.payload) if packet.haslayer(Raw) else 0

            data = bytes(ICMP_layer.payload) if packet.haslayer(Raw) else b""

            if self.verbose:
                click.echo(f"{idt}| ICMP Message at {receive_time}:")
                click.echo(f"{idt}\t- Type: {pkt_type}")
                click.echo(f"{idt}\t- Payload length: {payload_len}")
                click.echo(f"{idt}\t- Payload data: {data}\n")

            if self.log:
                logger.info(f"{idt}| ICMP Message at {receive_time}:")
                logger.info(f"{idt}\t- Type: {pkt_type}")
                logger.info(f"{idt}\t- Payload length: {payload_len}")
                logger.info(f"{idt}\t- Payload data: {data}\n")

            if idt == "":
                for i, encapsulating_layer in enumerate(self.encapsulating_layers.values()):
                    encapsulating_layer.handle_packet(packet, idt="\t" * (i+1))

    def get_icmp_type(self, p_type, p_code):
        return icmp_types.get((p_type, p_code), f"Undefined - type number & code: {p_type}, {p_code}")