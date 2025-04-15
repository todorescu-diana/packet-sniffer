import datetime
import click
from scapy.all import *
from pathlib import Path

from helpers.fct import packet_callback
from helpers.gen_const import valid_modes, valid_protocols

logger = logging.getLogger(__name__)

valid_modes_str = " / ".join(valid_modes)
valid_protocols_str = " / ".join(valid_protocols)

@click.command()
@click.option("--interface", default="WiFi", help="Interface on which to sniff packets; DEFAULT: WiFi")
@click.option("--mode", default=f"{valid_modes[2]}", help=f"Mode of operation; Options: {valid_modes_str}; DEFAULT: {valid_modes[2]}")
@click.option("--protocol", default=f"{valid_protocols[2]}", help=f"Protocol packets to capture & inspect; Options: {valid_protocols_str}; DEFAULT: {valid_protocols[2]}")
def main(interface, mode, protocol):
    try:
        if mode not in valid_modes:
            click.echo(f"[!] Invalid mode '{mode}'; Valid modes: {valid_modes_str}")
            exit(0)
        if protocol not in valid_protocols:
            click.echo(f"[!] Invalid protocol '{protocol}'; Valid protocols: {valid_protocols_str}")
            exit(0)
        
        if mode == "only-log" or mode == "log-live":
            now = datetime.now()
            current_datetime = now.strftime("%d-%m-%Y_%H-%M-%S")
            logfile_name = f"./logs/{protocol.upper()}_{interface}_{current_datetime}.log"

            folder = Path("./logs")
            folder.mkdir(parents=True, exist_ok=True) 

            logging.basicConfig(filename=logfile_name, level=logging.INFO, format="%(message)s")

            logger.info("[-] Started log\n")
            sniff(iface=interface, prn=lambda packet: packet_callback(packet, protocol, verbose=(mode == "log-live"), log=True), store=0)
            logger.info("[-] Succesfully stopped log")
        else:
            click.echo("[-] Started log\n")
            sniff(iface=interface, prn=lambda packet: packet_callback(packet, protocol), store=0)
            click.echo("[-] Succesfully stopped log")
    except Exception as e:
        click.echo(f"[!] Exited with error: {e}")
    finally:
        click.echo("[:)] Goodbye.")

if __name__ == "__main__":
    main()
