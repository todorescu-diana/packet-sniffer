from datetime import datetime as dt
import logging
import click
from classes.ProtocolHandler import ProtocolHandler
from scapy.all import *
from helpers.ip import *

logger = logging.getLogger(__name__)

class IPHandler(ProtocolHandler):
    def handle_packet(self, packet, idt=""):
        if packet.haslayer("IP"):     
            timestamp = packet.time
            time = dt.fromtimestamp(timestamp)
            receive_time = time.strftime("%d-%m-%Y %H:%M:%S")

            IP_layer = packet["IP"]

            src_ip = IP_layer.src
            dst_ip = IP_layer.dst
            version = IP_layer.version
            h_length = IP_layer.ihl

            tos = IP_layer.tos
            dscp = tos >> 2
            ecn = tos & 0x03

            dscp_class = self.get_dscp_class(dscp)
            ecn_map = self.get_ecn_map(ecn)

            total_length = IP_layer.len

            id = IP_layer.id

            flags = IP_layer.flags
            flags_map = self.get_flags_map(flags)

            ttl = IP_layer.ttl

            proto = IP_layer.proto
            proto_map = self.get_proto_map(proto)

            if self.verbose:
                click.echo(f"{idt}| IP Packet at {receive_time}")
                click.echo(f"{idt}\t- Version: {version}")
                click.echo(f"{idt}\t- Source: {src_ip}")
                click.echo(f"{idt}\t- Destination: {dst_ip}")
                click.echo(f"{idt}\t- Header length: {h_length} ({h_length * 4} bytes)")
                click.echo(f"{idt}\t- Type of service:")
                click.echo(f"{idt}\t\t[-] DSCP (Differentiated Services Code Point): {dscp} ({dscp_class})")
                click.echo(f"{idt}\t\t[-] ECN (Explicit Congestion Notification): {ecn} ({ecn_map})")
                click.echo(f"{idt}\t- Total length: {total_length} bytes")
                click.echo(f"{idt}\t- ID: {id}")
                click.echo(f"{idt}\t- Flags: {flags_map}")
                click.echo(f"{idt}\t- Time to Live: {ttl}")
                click.echo(f"{idt}\t- Encapsulated protocol: {proto_map}\n")

            if self.log:
                logger.info(f"{idt}| IP Packet at {receive_time}")
                logger.info(f"{idt}\t- Version: {version}")
                logger.info(f"{idt}\t- Source: {src_ip}")
                logger.info(f"{idt}\t- Destination: {dst_ip}")
                logger.info(f"{idt}\t- Header length: {h_length} ({h_length * 4} bytes)")
                logger.info(f"{idt}\t\t[-] DSCP (Differentiated Services Code Point): {dscp}")
                logger.info(f"{idt}\t\t[-] DSCP (Differentiated Services Code Point): {dscp} ({dscp_class})")
                logger.info(f"{idt}\t\t[-] ECN (Explicit Congestion Notification): {ecn} ({ecn_map})")
                logger.info(f"{idt}\t- Total length: {total_length} bytes")
                logger.info(f"{idt}\t- ID: {id}")
                logger.info(f"{idt}\t- Flags: {flags_map}")
                logger.info(f"{idt}\t- Time to Live: {ttl}")
                logger.info(f"{idt}\t- Encapsulated protocol: {proto_map}\n")

            if idt == "":
                for i, encapsulating_layer in enumerate(self.encapsulating_layers.values()):
                    encapsulating_layer.handle_packet(packet, idt="\t" * (i+1))

        elif packet.haslayer("IPv6"):
            timestamp = packet.time
            time = dt.fromtimestamp(timestamp)
            receive_time = time.strftime("%d-%m-%Y %H:%M:%S")

            IPv6_layer = packet["IPv6"]

            src_ip = IPv6_layer.src
            dst_ip = IPv6_layer.dst

            version = IPv6_layer.version
            traffic_class = IPv6_layer.tc
            dscp = traffic_class >> 2
            ecn = traffic_class & 0x03

            dscp_class = self.get_dscp_class(dscp)
            ecn_map = self.get_ecn_map(ecn)

            flow_label = IPv6_layer.fl
            packet_length = IPv6_layer.plen
            next_header = IPv6_layer.nh
            next_header_map = self.get_proto_map_6(next_header)
            hop_limit = IPv6_layer.hlim

            if self.verbose:
                click.echo(f"{idt}| IPv6 Packet at {receive_time}")
                click.echo(f"{idt}\t- Version: {version}")
                click.echo(f"{idt}\t- Traffic Class: {traffic_class} (DSCP: {dscp_class}, ECN: {ecn})")
                click.echo(f"{idt}\t- Flow label: {flow_label}")
                click.echo(f"{idt}\t- Packet Length: {packet_length}")
                click.echo(f"{idt}\t- Next Header: {next_header_map}")
                click.echo(f"{idt}\t- Hop Limit: {hop_limit}")
                click.echo(f"{idt}\t- Source: {src_ip}")
                click.echo(f"{idt}\t- Destination: {dst_ip}\n")

            if self.log:
                logger.info(f"{idt}| IPv6 Packet at {receive_time}")
                logger.info(f"{idt}\t- Version: {version}")
                logger.info(f"{idt}\t- Traffic Class: {traffic_class} (DSCP: {dscp_class}, ECN: {ecn})")
                logger.info(f"{idt}\t- Packet Length: {packet_length}")
                logger.info(f"{idt}\t- Next Header: {next_header_map}")
                logger.info(f"{idt}\t- Hop Limit: {hop_limit}")
                logger.info(f"{idt}\t- Source: {src_ip}")
                logger.info(f"{idt}\t- Destination: {dst_ip}\n")

            if idt == "":
                for i, encapsulating_layer in enumerate(self.encapsulating_layers.values()):
                    encapsulating_layer.handle_packet(packet, idt="\t" * (i+1))

    def get_dscp_class(self, dscp):
        return dscp_classes.get(dscp, f"Other: {dscp}")
    def get_ecn_map(self, ecn):
        return ecn_map.get(ecn, f"Other: {ecn}")
    def get_flags_map(self, flags):
        return flags_map.get(flags, f"Other: {flags}")
    def get_proto_map(self, proto):
        return proto_map.get(proto, f"Other: {proto}")
    def get_proto_map_6(self, proto):
        return proto_map_6.get(proto, f"Other: {proto}")