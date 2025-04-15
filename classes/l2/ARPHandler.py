from datetime import datetime as dt
import logging
import click
from classes.ProtocolHandler import ProtocolHandler
from helpers.arp import *

logger = logging.getLogger(__name__)

class ARPHandler(ProtocolHandler):
    def handle_packet(self, packet, idt=""):
        if packet.haslayer('ARP'):
            timestamp = packet.time
            time = dt.fromtimestamp(timestamp)
            receive_time = time.strftime("%d-%m-%Y %H:%M:%S")

            ARP_layer = packet["ARP"]

            packet_op = ARP_layer.op
            pkt_type = self.get_arp_type(packet_op)

            hw_src = ARP_layer.hwsrc
            ip_src = ARP_layer.psrc
        
            hw_dst = ARP_layer.hwdst
            ip_dst = ARP_layer.pdst

            hw_type = ARP_layer.hwtype
            p_type = ARP_layer.ptype
            hw_len = ARP_layer.hwlen
            p_len = ARP_layer.plen
            hw_type_extra = " (Ethernet)" if hw_type == 0x0001 else ""
            p_type_extra = " (IPv4)" if p_type == 0x0800 else ""

            info = f"Who has {ip_dst}? Tell {ip_src}" if "Request" in pkt_type else f"{ip_src} is at {hw_src}"

            if self.verbose:
                click.echo(f"{idt}| ARP Message at {receive_time}:")
                click.echo(f"{idt}\t- Type: {pkt_type}")
                click.echo(f"{idt}\t- Hardware type: {hw_type}{hw_type_extra}")
                click.echo(f"{idt}\t- Hardware length: {hw_len}")
                click.echo(f"{idt}\t- Protocol type: {p_type}")
                click.echo(f"{idt}\t- Protocol length: {p_len}{p_type_extra}")
                click.echo(f"{idt}\t- Sender MAC: {hw_src}")
                click.echo(f"{idt}\t- Sender IP: {ip_src}")
                click.echo(f"{idt}\t- Target MAC: {hw_dst}")
                click.echo(f"{idt}\t- Target IP: {ip_dst}")
                click.echo(f"{idt}\t- Info: {info}\n")

            if self.log:
                logger.info(f"{idt}| ARP Message at {receive_time}:")
                logger.info(f"{idt}\t- Type: {pkt_type}")
                logger.info(f"{idt}\t- Hardware type: {hw_type}{hw_type_extra}")
                logger.info(f"{idt}\t- Hardware length: {hw_len}")
                logger.info(f"{idt}\t- Protocol type: {p_type}{p_type_extra}")
                logger.info(f"{idt}\t- Protocol length: {p_len}")
                logger.info(f"{idt}\t- Sender MAC: {hw_src}")
                logger.info(f"{idt}\t- Sender IP: {ip_src}")
                logger.info(f"{idt}\t- Target MAC: {hw_dst}")
                logger.info(f"{idt}\t- Target IP: {ip_dst}")
                logger.info(f"{idt}\t- Info: {info}\n")

            if idt == "":
                for i, encapsulating_layer in enumerate(self.encapsulating_layers.values()):
                    encapsulating_layer.handle_packet(packet, idt="\t" * (i+1))
    def get_arp_type(self, a_op):
        return arp_types.get(a_op, f"Other: {a_op}")