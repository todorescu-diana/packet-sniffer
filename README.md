# Network Packet Sniffer
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

Packet Sniffer is a network packet sniffing command-line application developed with Python (using Scapy library).

It enables capturing, monitoring and analyzing incoming or outgoing packets on an interface.

The captured packets are shown in a tree-like structure, offering information about the fields of each layer they contain.

In case of TCP segments, if they use TLS, then the TLS records are also shown.

## Installation
- _python3_ can may have to be used instead of _python_, depending on your configuration.
### 1. Clone the repo
```
git clone https://github.com/todorescu-diana/packet-sniffer
```
```
cd packet-sniffer
```

### 2. Create and activate Python virutal environment
```
python -m venv venv
```

### 3. Activate virtual environment
* Windows
```
venv\Scripts\activate.bat
```
* Linux
```
source venv/bin/activate
```

### 4. Install required dependencies
```
pip install -r requirements.txt
```

## Usage
* Windows (may have to be run as admin)
```
python ./sniffer.py --interface <if> --mode <m> --protocol <proto>
```

* Linux
```
sudo ./venv/bin/python ./sniffer.py --interface <if> --mode <m> --protocol <proto>
```

* Displaying options:
```
python ./sniffer.py --help
```
```
Usage: sniffer.py [OPTIONS]

Options:
  --interface TEXT  Interface on which to sniff packets; DEFAULT: WiFi
  --mode TEXT       Mode of operation; Options: only-log / log-live / live;
                    DEFAULT: live
  --protocol TEXT   Protocol packets to capture & inspect; Options: arp / icmp / tcp / udp / dns; DEFAULT: tcp
  --help            Show this message and exit.
```

*  --mode option
```
only-log
```
Creates a log file and writes the output in the created log file.
```
log-live
```
Creates a log file and writes the output in the created log file, while also writing the output to the command line.
```
live
```
Only writes the output to the command line.

In case of only-log or log-live modes, logs are saved in the ./logs folder.

# Example outputs (with redacted values in <>)
* ARP

```
| ARP Message at 14-04-2025 22:14:40:
	- Type: ARP Request
	- Hardware type: 1 (Ethernet)
	- Hardware length: 6
	- Protocol type: 2048 (IPv4)
	- Protocol length: 4
	- Sender MAC: <s_mac>
	- Sender IP: <s_ip>
	- Target MAC: <t_mac>
	- Target IP: <t_ip>
	- Info: Who has <t_ip>? Tell <s_ip>

	| Ethernet Frame at 14-04-2025 22:14:40:
		- Source: <src_mac>
		- Destination: <dest_mac>
		- Payload type: ARP
```

```
| ARP Message at 14-04-2025 22:14:40:
	- Type: ARP Reply
	- Hardware type: 1 (Ethernet)
	- Hardware length: 6
	- Protocol type: 2048 (IPv4)
	- Protocol length: 4
	- Sender MAC: <s_mac>
	- Sender IP: <s_ip>
	- Target MAC: <t_mac>
	- Target IP: <t_ip>
	- Info: <s_ip> is at <s_mac>

	| Ethernet Frame at 14-04-2025 22:14:40:
		- Source: <src_mac>
		- Destination: <dest_mac>
		- Payload type: ARP
```

* ICMP
```
| ICMP Message at 14-04-2025 22:40:22:
	- Type: Echo Request
	- Payload length: <payload_length>
	- Payload data: <payload_data>

	| IP Packet at 14-04-2025 22:40:22
		- Version: 4
		- Source: <src_ip>
		- Destination: <dest_ip>
		- Header length: 5 (20 bytes)
			[-] DSCP (Differentiated Services Code Point): 0
			[-] DSCP (Differentiated Services Code Point): 0 (Default)
			[-] ECN (Explicit Congestion Notification): 0 (Not ECN-Capable Transport)
		- Total length: <total_length>
		- ID: 21312
		- Flags: No flags set (0x0)
		- Time to Live: 64
		- Encapsulated protocol: ICMP

		| Ethernet Frame at 14-04-2025 22:40:22:
			- Source: <src_mac>
			- Destination: <dest_mac>
			- Payload type: IPv4
```

```
| ICMP Message at 14-04-2025 22:41:59:
	- Type: Echo Request
	- Payload length: <payload_length>
	- Payload data: <payload_data>

	| IP Packet at 14-04-2025 22:41:59
		- Version: 4
		- Source: <src_ip>
		- Destination: <dest_ip>
		- Header length: 5 (20 bytes)
			[-] DSCP (Differentiated Services Code Point): 0
			[-] DSCP (Differentiated Services Code Point): 0 (Default)
			[-] ECN (Explicit Congestion Notification): 0 (Not ECN-Capable Transport)
		- Total length: <total_length>
		- ID: 6611
		- Flags: No flags set (0x0)
		- Time to Live: 128
		- Encapsulated protocol: ICMP

		| Ethernet Frame at 14-04-2025 22:41:59:
			- Source: <src_mac>
			- Destination: <dest_mac>
			- Payload type: IPv4
```

* TCP
```
| Transport Layer Security
	- Content type: TLS Handshake
	- Version: TLS 1.2
	- Length: <tls_length>
	- TLS Handshake Protocol: ServerHello
	- Length: <handshake_length>
	- Version: TLS 1.2 (DEPRECATED; see supported_versions present instead)
	- Random: <random>
	- Session ID length: <s_id_length>
	- Session ID: <s_id>
	- Chosen Cipher Suite: TLS_AES_256_GCM_SHA384
	- Compression Method: null (0)
	- Extensions length: 52
		[-] Extension: supported_versions
			[--] Type: supported_versions
			[--] Length: 2
			[--] Data: b'\x03\x04'
		[-] Extension: key_share
			[--] Type: key_share
			[--] Length: <key_share_length>
			[--] Data: <key_share>
		[-] Extension: Other: (0, 41)
			[--] Type: Other: (0, 41)
			[--] Length: 2
			[--] Data: <data>
| Transport Layer Security
	- Content type: TLS ChangeCipherSpec
	- Version: TLS 1.2
	- Length: 1
	- Change Cipher Spec Message: 1
| Transport Layer Security
	- Content type: TLS Application data
	- Version: TLS 1.2
	- Length: <data_length>
	- Encrypted application data: <enc_data>
| Transport Layer Security
	- Content type: TLS Application data
	- Version: TLS 1.2
	- Length: <data_length>
	- Encrypted application data: <enc_data>

	| TCP Segment at 14-04-2025 22:26:32:
		- Source port: <s_port>
		- Destination port: <d_port>
		- Sequence number: <seq_number>
		- Acknowledgement number: <ack_number>
		- Payload length: <payload_length>
		- Payload data: <payload_data>
		- Window size: 501 bytes
		- Type: PSH-ACK

		| IPv6 Packet at 14-04-2025 22:26:32
			- Version: 6
			- Traffic Class: 0 (DSCP: Default, ECN: 0)
			- Packet Length: <packet_length>
			- Next Header: TCP
			- Hop Limit: 60
			- Source: <src_ipv6_addr>
			- Destination: <dest_ipv6_addr>

			| Ethernet Frame at 14-04-2025 22:26:32:
				- Source: <src_mac>
				- Destination: <dest_mac>
				- Payload type: IPv6
```

* UDP
```
| UDP Datagram at 14-04-2025 22:34:34:
	- Source port: <s_port>
	- Destination port: <d_port>
	- Payload length: <payload_length>
	- Payload data: <payload_data>

	| IPv6 Packet at 14-04-2025 22:34:34
		- Version: 6
		- Traffic Class: 0 (DSCP: Default, ECN: 0)
		- Packet Length: <packet_length>
		- Next Header: UDP
		- Hop Limit: 64
		- Source: <src_ipv6_addr>
		- Destination: <dest_ipv6_addr>

		| Ethernet Frame at 14-04-2025 22:34:34:
			- Source: <src_mac>
			- Destination: <dest_mac>
			- Payload type: IPv6
```

* DNS
```
| DNS Message at 14-04-2025 22:15:35:
	- ID: 15395
	- QR: DNS Query
	- RD: Recursion Not Desired
	- Question count: 1
		[1.] Question name: <q>
		- DNS record type: AAAA (IPv6 Address)

	| UDP Datagram at 14-04-2025 22:15:35:
		- Source port: <s_port>
		- Destination port: <d_port>
		- Payload length: <payload_length>
		- Payload data: <payload_data>

		| IPv6 Packet at 14-04-2025 22:15:35
			- Version: 6
			- Traffic Class: 0 (DSCP: Default, ECN: 0)
			- Packet Length: <packet_length>
			- Next Header: UDP
			- Hop Limit: 64
			- Source: <src_ipv6_addr>
			- Destination: <dest_ipv6_addr>

			| Ethernet Frame at 14-04-2025 22:15:35:
				- Source: <src_mac>
				- Destination: <dest_mac>
				- Payload type: IPv6
```

```
| DNS Message at 14-04-2025 22:20:35:
	- ID: 23164
	- QR: DNS Response
	- RD: Recursion Not Desired
	- AA: Non-Authoritative
	- RCODE: 0
	- Answer count: 9
		[1.] Answer name: <a>
		- DNS record type: CNAME (Canonical Name)
		[2.] Answer name: <a>
		- DNS record type: CNAME (Canonical Name)
		[3.] Answer name: <a>
		- DNS record type: CNAME (Canonical Name)
		[4.] Answer name: <a>
		- DNS record type: CNAME (Canonical Name)
		[5.] Answer name: <a>
		- DNS record type: CNAME (Canonical Name)
		[6.] Answer name: <a>
		- DNS record type: AAAA (IPv6 Address)
		[7.] Answer name: <a>
		- DNS record type: AAAA (IPv6 Address)
		[8.] Answer name: <a>
		- DNS record type: AAAA (IPv6 Address)
		[9.] Answer name: <a>
		- DNS record type: AAAA (IPv6 Address)

	| UDP Datagram at 14-04-2025 22:20:35:
		- Source port: <s_port>
		- Destination port: <d_port>
		- Payload length: <payload_length>
		- Payload data: <payload_data>

		| IPv6 Packet at 14-04-2025 22:20:35
			- Version: 6
			- Traffic Class: 0 (DSCP: Default, ECN: 0)
			- Packet Length: <packet_length>
			- Next Header: UDP
			- Hop Limit: 64
			- Source: <src_ipv6_addr>
			- Destination: <dest_ipv6_addr>

			| Ethernet Frame at 14-04-2025 22:20:35:
				- Source: <src_mac>
				- Destination: <dest_mac>
				- Payload type: IPv6
```