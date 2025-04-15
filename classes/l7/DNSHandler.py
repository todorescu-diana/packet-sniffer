from datetime import datetime as dt
import logging
import click
from scapy.all import *
from classes.ProtocolHandler import ProtocolHandler

logger = logging.getLogger(__name__)

dns_qr = {
    0: "DNS Query",
    1: "DNS Response"
}

dns_aa = {
    0: "Non-Authoritative",
    1: "Authoritative"
}

dns_rd = {
    0: "Recursion Desired",
    1: "Recursion Not Desired"
}

dns_records = {
    1: "A (IPv4 Address)",
    28: "AAAA (IPv6 Address)",
    5: "CNAME (Canonical Name)",
    15: "MX (Mail Exchange)",
    2: "NS (Name Server)",
    12: "PTR (Pointer)",
    6: "SOA (Start of Authority)",
    65: "HTTPS-based DNS (DoH)",
    33: "SRV",
}

class DNSHandler(ProtocolHandler):
    def handle_packet(self, packet, idt=""):
        if packet.haslayer('DNS'):
            timestamp = packet.time
            time = dt.fromtimestamp(timestamp)
            receive_time = time.strftime("%d-%m-%Y %H:%M:%S")

            DNS_layer = packet["DNS"]

            packet_id = DNS_layer.id
            packet_qr = DNS_layer.qr
            packet_aa = DNS_layer.aa
            packet_rd = DNS_layer.rd
            packet_rcode = DNS_layer.rcode
            packet_qdcount = DNS_layer.qdcount
            packet_ancount = DNS_layer.ancount

            qr = self.get_dns_qr(packet_qr)
            aa = self.get_dns_aa(packet_aa)
            rd = self.get_dns_rd(packet_rd)

            if packet_qr == 0:
                questions = DNS_layer.qd
            else:
                answers = DNS_layer.an

            if self.verbose:
                click.echo(f"| DNS Message at {receive_time}:")
                click.echo(f"\t- ID: {packet_id}")
                click.echo(f"\t- QR: {qr}")
                click.echo(f"\t- RD: {rd}")
                if packet_qr == 1:
                    click.echo(f"\t- AA: {aa}")
                    click.echo(f"\t- RCODE: {packet_rcode}")
                    click.echo(f"\t- Answer count: {packet_ancount}")
                    for i, answer in enumerate(answers):
                        click.echo(f"\t\t[{i+1}.] Answer name: {answer.rrname}")
                        click.echo(f"\t\t- DNS record type: {self.get_dns_r_type(answer.type)}")
                else:
                    click.echo(f"\t- Question count: {packet_qdcount}")
                    for i, question in enumerate(questions):
                        click.echo(f"\t\t[{i+1}.] Question name: {question.qname}")
                        click.echo(f"\t\t- DNS record type: {self.get_dns_r_type(question.qtype)}")
                click.echo("")

            if self.log:
                logger.info(f"| DNS Message at {receive_time}:")
                logger.info(f"\t- ID: {packet_id}")
                logger.info(f"\t- QR: {qr}")
                logger.info(f"\t- RD: {rd}")
                if packet_qr == 1:
                    logger.info(f"\t- AA: {aa}")
                    logger.info(f"\t- RCODE: {packet_rcode}")
                    logger.info(f"\t- Answer count: {packet_ancount}")
                    for i, answer in enumerate(answers):
                        logger.info(f"\t\t[{i+1}.] Answer name: {answer.rrname}")
                        logger.info(f"\t\t- DNS record type: {self.get_dns_r_type(answer.type)}")
                else:
                    logger.info(f"\t- Question count: {packet_qdcount}")
                    for i, question in enumerate(questions):
                        logger.info(f"\t\t[{i+1}.] Question name: {question.qname}")
                        logger.info(f"\t\t- DNS record type: {self.get_dns_r_type(question.qtype)}")
                logger.info("")

            if idt == "": # upper-most layer in stack
                for i, encapsulating_layer in enumerate(self.encapsulating_layers.values()):
                    encapsulating_layer.handle_packet(packet, idt="\t" * (i+1))

    def get_dns_qr(self, p_qr):
        return dns_qr.get(p_qr)
    def get_dns_aa(self, p_aa):
        return dns_aa.get(p_aa)
    def get_dns_rd(self, p_rd):
        return dns_rd.get(p_rd)
    def get_dns_r_type(self, p_record_type):
        return dns_records.get(p_record_type, f"Other: {p_record_type}")