from datetime import datetime as dt
import logging
import click
from classes.ProtocolHandler import ProtocolHandler
from helpers.ether import *

logger = logging.getLogger(__name__)

class EthernetHandler(ProtocolHandler):
    def handle_packet(self, packet, idt=""):
        if packet.haslayer('Ether'):
            timestamp = packet.time
            time = dt.fromtimestamp(timestamp)
            receive_time = time.strftime("%d-%m-%Y %H:%M:%S")

            Ether_layer = packet["Ether"]

            src = Ether_layer.src
            dst = Ether_layer.dst
            e_type = Ether_layer.type
            ether_type = self.get_ether_type(e_type)

            if self.verbose:
                click.echo(f"{idt}| Ethernet Frame at {receive_time}:")
                click.echo(f"{idt}\t- Source: {src}")
                click.echo(f"{idt}\t- Destination: {dst}")
                click.echo(f"{idt}\t- Payload type: {ether_type}\n")

            if self.log:
                logger.info(f"{idt}| Ethernet Frame at {receive_time}:")
                logger.info(f"{idt}\t- Source: {src}")
                logger.info(f"{idt}\t- Destination: {dst}")
                logger.info(f"{idt}\t- Payload type: {ether_type}\n")

    def get_ether_type(self, ether_type):
        return ether_types.get(ether_type, f"Other: {ether_type}")