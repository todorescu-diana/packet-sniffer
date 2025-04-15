from datetime import datetime as dt
from scapy.all import *
import click
import logging
from classes.ProtocolHandler import ProtocolHandler
from helpers.tcp_tls import *

logger = logging.getLogger(__name__)

class TCP_TLSHandler():
    def check_tls_https(self, TCP_layer):
        raw = bytes(TCP_layer.payload)
        if raw and raw[0] in tls_content_type_map.keys() and (raw[1], raw[2]) in tls_version_map.keys(): # probably TLS.
            return True
        return False
    def handle_packet(self, payload_bytes, tcp_type, TCP_layer, cache, verbose, log):
        raw = payload_bytes
        sequence_number = TCP_layer.seq
        acknowledgement_number = TCP_layer.ack if 'ACK' in tcp_type else None

        more_tls = False

        tls_content_type = self.get_tls_content_type(raw[0])
        tls_version = self.get_tls_version(raw[1], raw[2])
        tls_length = (raw[3] << 8) | raw[4]

        next_tls = -1
        if len(raw) > 5 + tls_length:
            more_tls = True

        if "Application data" in tls_content_type:
                enc_app_data = raw[5:next_tls] if next_tls > -1 else raw[5:]

        elif "Handshake" in tls_content_type:
                handshake_data = raw[5:next_tls] if next_tls > -1 else raw[5:]
                cache_flag = 0

                for entry in cache:
                    if entry.get("ack_number") == acknowledgement_number and sequence_number == entry.get("seq_number") + entry.get("payload_len"):
                        handshake_data = handshake_data + entry.get("data")
                        cache_flag = 1
                        break
                
                h_type = self.get_tls_handshake_type(handshake_data[0])
                h_length = handshake_data[1] << 16 | handshake_data[2] << 8 | handshake_data[3]

                if h_type == "ClientHello":
                    client_hello_info = self.get_client_hello_info(handshake_data, cache_flag)
                elif h_type == "ServerHello":
                    server_hello_info = self.get_server_hello_info(handshake_data, cache_flag)
        elif "ChangeCipherSpec" in tls_content_type:
            change_cipher_spec_message = raw[5]

        if verbose:
            click.echo(f"| Transport Layer Security")
            click.echo(f"\t- Content type: {tls_content_type}")
            click.echo(f"\t- Version: {tls_version}")
            click.echo(f"\t- Length: {tls_length}")
            if "Application data" in tls_content_type:
                click.echo(f"\t- Encrypted application data: {enc_app_data}")
            elif "Handshake" in tls_content_type:
                click.echo(f"\t- TLS Handshake Protocol: {h_type}")
                click.echo(f"\t- Length: {h_length}")
                if h_type == "ClientHello":
                    self.print_client_hello_info(client_hello_info, cache_flag, verbose=True)
                elif h_type == "ServerHello":
                    self.print_server_hello_info(server_hello_info, cache_flag, verbose=True)
            elif "ChangeCipherSpec" in tls_content_type:
                click.echo(f"\t- Change Cipher Spec Message: {change_cipher_spec_message}")

            if more_tls is not True:
                click.echo("")

        if log:
            logger.info(f"| Transport Layer Security")
            logger.info(f"\t- Content type: {tls_content_type}")
            logger.info(f"\t- Version: {tls_version}")
            logger.info(f"\t- Length: {tls_length}")
            if "Application data" in tls_content_type:
                logger.info(f"\t- Encrypted application data: {enc_app_data}")
            elif "Handshake" in tls_content_type:
                logger.info(f"\t- TLS Handshake Protocol: {h_type}")
                logger.info(f"\t- Length: {h_length}")
                if h_type == "ClientHello":
                    self.print_client_hello_info(client_hello_info, cache_flag, log=True)
                elif h_type == "ServerHello":
                    self.print_server_hello_info(server_hello_info, cache_flag, log=True)
            elif "ChangeCipherSpec" in tls_content_type:
                logger.info(f"\t- Change Cipher Spec Message: {change_cipher_spec_message}")

            if more_tls is not True:
                logger.info("")

            if more_tls is True:
                next_tls = 5 + tls_length
                self.handle_packet(raw[next_tls:], tcp_type, TCP_layer, cache, verbose, log)

    def get_tls_content_type(self, b):
        return tls_content_type_map.get(b, f"Other: {b}")
    def get_tls_version(self, b1, b2):
        return tls_version_map.get((b1, b2), f"Other: {(b1, b2)}")
    def get_tls_handshake_type(self, b):
        return tls_handshake_type_map.get(b, f"Other: {b}")
    def get_handshake_cipher_suite(self, b1, b2):
        return cipher_suite_map.get((b1, b2), f"Other: {(b1, b2)}")
    def get_handshake_extension(self, b1, b2):
        return extensions_map.get((b1, b2), f"Other: {(b1, b2)}")
    
    def get_client_hello_info(self, handshake_data, cache_flag):
        h_version = self.get_tls_version(handshake_data[4], handshake_data[5])
        h_random = handshake_data[6:38]
        h_session_id_length = handshake_data[38]
        idx_session_id_stop = 39 + h_session_id_length
        h_session_id = None
        if h_session_id_length > 0:
            h_session_id = handshake_data[39:idx_session_id_stop]
            
        h_cipher_suites_length = handshake_data[idx_session_id_stop] << 8 | handshake_data[idx_session_id_stop + 1]

        idx_cipher_start = idx_session_id_stop + 2
        idx_cipher_stop = idx_cipher_start + h_cipher_suites_length

        cipher_suite_list = []

        for i in range(idx_cipher_start, idx_cipher_stop, 2):
            cipher_suite = self.get_handshake_cipher_suite(handshake_data[i], handshake_data[i+1])
            cipher_suite_list.append(cipher_suite)

        h_compression_methods_len = handshake_data[idx_cipher_stop]

        idx_compression_start = idx_cipher_stop + 1
        idx_compression_stop = idx_compression_start + h_compression_methods_len
        compression_method_strings = []

        for i in range(idx_compression_start, idx_compression_stop):
            compression_method = handshake_data[i]
            compression_method_str = ""
            if compression_method == 0x00:
                compression_method_str = "null (0)"
            elif compression_method == 0x01:
                compression_method_str = "DEFLATE (1)"
            else:
                compression_method_str = "Other"
            if len(compression_method_str) > 0:
                compression_method_strings.append(compression_method_str)

        h_extensions_length = handshake_data[idx_compression_stop] << 8 | handshake_data[idx_compression_stop + 1]
        idx_extensions_start = idx_compression_stop + 2

        h_extensions = []
        proc_ext_bytes = 0

        i = idx_extensions_start

        if cache_flag != 1:
            while proc_ext_bytes < h_extensions_length:
                ext_type = self.get_handshake_extension(handshake_data[i], handshake_data[i+1])
                ext_length = handshake_data[i+2] << 8 | handshake_data[i+3]
                ext_data = None
                if ext_length > 0:
                    ext_data = handshake_data[i+4:i+4+ext_length]
                h_extensions.append({"type": ext_type, "length": ext_length, "data": ext_data})

                i += 4 + ext_length
                proc_ext_bytes += 4 + ext_length

        return (h_version, h_random, h_session_id_length, h_session_id, h_cipher_suites_length, cipher_suite_list, h_compression_methods_len, compression_method_strings, h_extensions_length, h_extensions)
    
    def print_client_hello_info(self, client_hello_info, cache_flag, verbose=False, log=False):
        h_version, h_random, h_session_id_length, h_session_id, h_cipher_suites_length, cipher_suite_list, h_compression_methods_len, compression_method_strings, h_extensions_length, h_extensions = client_hello_info
        
        supported_ext_present = any(d["type"] == "supported_versions" for d in h_extensions)
        additional_version_info = " (DEPRECATED; see supported_versions present instead)" if "1.2" in h_version and supported_ext_present is True else "" 

        if verbose is True:
            click.echo(f"\t- Version: {h_version}{additional_version_info}")
            click.echo(f"\t- Random: {h_random}")
            click.echo(f"\t- Session ID length: {h_session_id_length}")
            if h_session_id_length > 0 and h_session_id is not None:
                click.echo(f"\t- Session ID: {h_session_id}")
            click.echo(f"\t- Cipher Suites Length: {h_cipher_suites_length}")
            click.echo(f"\t- Cipher Suites ({len(cipher_suite_list)}):")
            for cipher_suite in cipher_suite_list:
                click.echo(f"\t\t[-] {cipher_suite}")
            click.echo(f"\t- Compression Methods ({h_compression_methods_len}):")
            for compression_method in compression_method_strings:
                click.echo(f"\t\t[-] {compression_method}")
            click.echo(f"\t- Extensions length: {h_extensions_length}")

            if cache_flag != 1:
                for extension in h_extensions:
                    click.echo(f"\t\t[-] Extension: {extension['type']}")
                    click.echo(f"\t\t\t[--] Type: {extension['type']}")
                    click.echo(f"\t\t\t[--] Length: {extension['length']}")
                    click.echo(f"\t\t\t[--] Data: {extension['data']}")
            else:
                click.echo(f"\t\t\t[--] Fragmented extension data")
            
        if log is True:
            logger.info(f"\t- Version: {h_version}{additional_version_info}")
            logger.info(f"\t- Random: {h_random}")
            logger.info(f"\t- Session ID length: {h_session_id_length}")
            if h_session_id_length > 0 and h_session_id is not None:
                logger.info(f"\t- Session ID: {h_session_id}")
            logger.info(f"\t- Cipher Suites Length: {h_cipher_suites_length}")
            logger.info(f"\t- Cipher Suites ({len(cipher_suite_list)}):")
            for cipher_suite in cipher_suite_list:
                logger.info(f"\t\t[-] {cipher_suite}")
            logger.info(f"\t- Compression Methods ({h_compression_methods_len}):")
            for compression_method in compression_method_strings:
                logger.info(f"\t\t[-] {compression_method}")
            logger.info(f"\t- Extensions length: {h_extensions_length}")

            if cache_flag != 1:
                for extension in h_extensions:
                    logger.info(f"\t\t[-] Extension: {extension['type']}")
                    logger.info(f"\t\t\t[--] Type: {extension['type']}")
                    logger.info(f"\t\t\t[--] Length: {extension['length']}")
                    logger.info(f"\t\t\t[--] Data: {extension['data']}")
            else:
                logger.info(f"\t\t\t[--] Fragmented extension data")
        

    def get_server_hello_info(self, handshake_data, cache_flag):
        h_version = self.get_tls_version(handshake_data[4], handshake_data[5])
        h_random = handshake_data[6:38]
        h_session_id_length = handshake_data[38]
        idx_session_id_stop = 39 + h_session_id_length
        h_session_id = None
        if h_session_id_length > 0:
            h_session_id = handshake_data[39:idx_session_id_stop]
    
        h_cipher_suite = self.get_handshake_cipher_suite(handshake_data[idx_session_id_stop], handshake_data[idx_session_id_stop + 1])

        h_compression_method = handshake_data[idx_session_id_stop+2]

        compression_method_str = ""
        if h_compression_method == 0x00:
            compression_method_str = "null (0)"
        else:
            compression_method_str = "Other"

        h_extensions_length = handshake_data[idx_session_id_stop + 3] << 8 | handshake_data[idx_session_id_stop + 4]
        idx_extensions_start = idx_session_id_stop + 5

        h_extensions = []
        proc_ext_bytes = 0

        i = idx_extensions_start

        if cache_flag != 1:
            while proc_ext_bytes < h_extensions_length:
                
                ext_type = self.get_handshake_extension(handshake_data[i], handshake_data[i+1])
                ext_length = handshake_data[i+2] << 8 | handshake_data[i+3]
                ext_data = None
                if ext_length > 0:
                    ext_data = handshake_data[i+4:i+4+ext_length]
                h_extensions.append({"type": ext_type, "length": ext_length, "data": ext_data})

                i += 4 + ext_length
                proc_ext_bytes += 4 + ext_length

        return (h_version, h_random, h_session_id_length, h_session_id, h_cipher_suite, compression_method_str, h_extensions_length, h_extensions)
    
    def print_server_hello_info(self, server_hello_info, cache_flag, verbose=False, log=False):
        h_version, h_random, h_session_id_length, h_session_id, h_cipher_suite, compression_method_str, h_extensions_length, h_extensions = server_hello_info

        supported_ext_present = any(d["type"] == "supported_versions" for d in h_extensions)
        additional_version_info = " (DEPRECATED; see supported_versions present instead)" if "1.2" in h_version and supported_ext_present is True else "" 
        if verbose is True:
            click.echo(f"\t- Version: {h_version}{additional_version_info}")
            click.echo(f"\t- Random: {h_random}")
            click.echo(f"\t- Session ID length: {h_session_id_length}")
            if h_session_id_length > 0 and h_session_id is not None:
                click.echo(f"\t- Session ID: {h_session_id}")
            click.echo(f"\t- Chosen Cipher Suite: {h_cipher_suite}")
            click.echo(f"\t- Compression Method: {compression_method_str}")
            click.echo(f"\t- Extensions length: {h_extensions_length}")

            if cache_flag != 1:
                for extension in h_extensions:
                    click.echo(f"\t\t[-] Extension: {extension['type']}")
                    click.echo(f"\t\t\t[--] Type: {extension['type']}")
                    click.echo(f"\t\t\t[--] Length: {extension['length']}")
                    click.echo(f"\t\t\t[--] Data: {extension['data']}")
            else:
                click.echo(f"\t\t\t[--] Fragmented extension data")
            
        if log is True:
            logger.info(f"\t- Version: {h_version}{additional_version_info}")
            logger.info(f"\t- Random: {h_random}")
            logger.info(f"\t- Session ID length: {h_session_id_length}")
            if h_session_id_length > 0 and h_session_id is not None:
                logger.info(f"\t- Session ID: {h_session_id}")
            logger.info(f"\t- Chosen Cipher Suite: {h_cipher_suite}")
            logger.info(f"\t- Compression Method: {compression_method_str}")
            logger.info(f"\t- Extensions length: {h_extensions_length}")

            if cache_flag != 1:
                for extension in h_extensions:
                    logger.info(f"\t\t[-] Extension: {extension['type']}")
                    logger.info(f"\t\t\t[--] Type: {extension['type']}")
                    logger.info(f"\t\t\t[--] Length: {extension['length']}")
                    logger.info(f"\t\t\t[--] Data: {extension['data']}")
            else:
                logger.info(f"\t\t\t[--] Fragmented extension data")