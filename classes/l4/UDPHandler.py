from datetime import datetime as dt
import click
from scapy.all import *
import logging

from classes.ProtocolHandler import ProtocolHandler

logger = logging.getLogger(__name__)

class UDPHandler(ProtocolHandler):
    def handle_packet(self, packet, idt=""):
        if packet.haslayer('UDP'):
            timestamp = packet.time
            time = dt.fromtimestamp(timestamp)
            receive_time = time.strftime("%d-%m-%Y %H:%M:%S")

            UDP_layer = packet["UDP"]
            
            src_port = UDP_layer.sport
            dst_port = UDP_layer.dport

            payload_len = len(UDP_layer.payload)

            data = bytes(UDP_layer.payload)

            if self.verbose:
                click.echo(f"{idt}| UDP Datagram at {receive_time}:")
                click.echo(f"{idt}\t- Source port: {src_port}")
                click.echo(f"{idt}\t- Destination port: {dst_port}")
                click.echo(f"{idt}\t- Payload length: {payload_len}")
                click.echo(f"{idt}\t- Payload data: {data}\n")

            if self.log:
                logger.info(f"{idt}| UDP Datagram at {receive_time}:")
                logger.info(f"{idt}\t- Source port: {src_port}")
                logger.info(f"{idt}\t- Destination port: {dst_port}")
                logger.info(f"{idt}\t- Payload length: {payload_len}")
                logger.info(f"{idt}\t- Payload data: {data}\n")

            if idt == "": # upper-most layer in stack
                for i, encapsulating_layer in enumerate(self.encapsulating_layers.values()):
                    encapsulating_layer.handle_packet(packet, idt="\t" * (i+1))
