from datetime import datetime as dt
from scapy.all import *
import click
import logging
from classes.ProtocolHandler import ProtocolHandler
from classes.l6.TCP_TLSHandler import TCP_TLSHandler
from helpers.tcp import *

logger = logging.getLogger(__name__)

class TCPHandler(ProtocolHandler):
    def handle_packet(self, packet, idt=""):
        if packet.haslayer('TCP'):
            timestamp = packet.time
            time = dt.fromtimestamp(timestamp)
            receive_time = time.strftime("%d-%m-%Y %H:%M:%S")

            tls_idt = ""

            TCP_layer = packet["TCP"]

            src_port = TCP_layer.sport
            dst_port = TCP_layer.dport

            tcp_flag = TCP_layer.flags
            tcp_type = self.get_tcp_type(str(tcp_flag))

            sequence_number = TCP_layer.seq
            acknowledgement_number = TCP_layer.ack if 'ACK' in tcp_type else None

            payload_len = len(TCP_layer.payload) if packet.haslayer(Raw) else 0
            data = bytes(TCP_layer.payload) if packet.haslayer(Raw) else b""

            window = TCP_layer.window

            # first check for HTTPS
            tls_handler = TCP_TLSHandler()
            if tls_handler.check_tls_https(TCP_layer) is True:
                tls_idt = "\t"
                tls_handler.handle_packet(bytes(TCP_layer.payload), tcp_type, TCP_layer, self.cache, self.verbose, self.log)

            if self.verbose:
                click.echo(f"{tls_idt}| TCP Segment at {receive_time}:")
                click.echo(f"{tls_idt}\t- Source port: {src_port}")
                click.echo(f"{tls_idt}\t- Destination port: {dst_port}")
                click.echo(f"{tls_idt}\t- Sequence number: {sequence_number}")
                if acknowledgement_number is not None: 
                    click.echo(f"{tls_idt}\t- Acknowledgement number: {acknowledgement_number}")
                click.echo(f"{tls_idt}\t- Payload length: {payload_len}")
                click.echo(f"{tls_idt}\t- Payload data: {data}")
                click.echo(f"{tls_idt}\t- Window size: {window} bytes")
                click.echo(f"{tls_idt}\t- Type: {tcp_type}\n")

            if self.log:
                logger.info(f"{tls_idt}| TCP Segment at {receive_time}:")
                logger.info(f"{tls_idt}\t- Source port: {src_port}")
                logger.info(f"{tls_idt}\t- Destination port: {dst_port}")
                logger.info(f"{tls_idt}\t- Sequence number: {sequence_number}")
                if acknowledgement_number is not None: 
                    logger.info(f"{tls_idt}\t- Acknowledgement number: {acknowledgement_number}")
                logger.info(f"{tls_idt}\t- Payload length: {payload_len}")
                logger.info(f"{tls_idt}\t- Payload data: {data}")
                logger.info(f"{tls_idt}\t- Window size: {window} bytes")
                logger.info(f"{tls_idt}\t- Type: {tcp_type}\n")

            self.cache.append({"ack_number": acknowledgement_number, "seq_number": sequence_number, "data": data, "payload_len": payload_len})
            if len(self.cache) > 10:
                self.cache.pop(0)

            if idt == "": # upper-most layer in stack
                for i, encapsulating_layer in enumerate(self.encapsulating_layers.values()):
                    encapsulating_layer.handle_packet(packet, idt=tls_idt + "\t" * (i+1))

    def get_tcp_type(self, flag):
        return tcp_types.get(flag, f"Other: {flag}")