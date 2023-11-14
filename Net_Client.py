from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import dns.message
import dns.rdatatype
import socket
from time import sleep

def get_DHCP_IP():
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))  # connect to a remote host
        router_ip = s.getsockname()[0]  # get the local IP address
        router_ip_prefix = router_ip.split(".")[:-2]
        router_ip_prefix = ".".join(router_ip_prefix) + "." + str(int(router_ip.split(".")[2]) + 1)
    return router_ip_prefix + ".1"

my_dhcp_ip = get_DHCP_IP()

def get_mac():
    return get_if_hwaddr(conf.iface)

# Ask for a random IP
def send_discover(src_mac):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / \
          UDP(dport=67, sport=68) / BOOTP(op=1, chaddr=src_mac) / DHCP(options=[('message-type', 'discover'), 'end'])
    sendp(pkt, iface=conf.iface)

# Define a function to handle DHCP Offer packets and print the IP address
def __handle_DHCP_offer(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 2:
        print("Received DHCP offer.")
        print("Server IP address: ", pkt[IP].src)
        print("Offered IP address: ", pkt[BOOTP].yiaddr)

# Sniff IP from DHCP Offer packet
def receive_offer():
    # Set up a sniffing filter for DHCP Offer packets
    sniff_filter = "udp and (port 67 or 68) and host " + my_dhcp_ip

    # Start sniffing for DHCP Offer packets
    return sniff(filter=sniff_filter, prn=__handle_DHCP_offer, timeout=3)

# Send a DHCP request to check for conflicts with other DHCP servers
def send_request(src_mac, req_ip, server_ip):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / \
          UDP(dport=67, sport=68) / BOOTP(op=1, chaddr=src_mac) / \
          DHCP(options=[('message-type', 'request'), ("client_id", src_mac), ("requested_addr", req_ip),
                        ("server_id", server_ip), 'end'])
    sendp(pkt, iface=conf.iface)

# Check for DHCP ACK packet
def receive_acknowledge():
    try:
        pkt = sniff(iface=conf.iface, filter="port 68 and port 67 and host " + my_dhcp_ip,
                    stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[DHCP].options[0][1] == 5,
                    timeout=8)
        if not pkt:
            raise Scapy_Exception("Timeout.")
        return pkt
    
    except Scapy_Exception as e:
        print(e)
        return "Timeout"

def send_DNS_query(dns_server_addr, client_ip ,client_port):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((client_ip, client_port))

    # Set the domain name to resolve
    domainName = "ftpdrive.org"

    # Create the DNS query packet
    dns_pkt = b"\x31\x0d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c\x66\x74\x70\x64\x72\x69\x76\x65\x2e\x6f\x72\x67\x00\x00\x01\x00\x01"
    '''
    Transaction ID: 0x31 0x0d
    A 16-bit value that identifies the DNS query and is used to match query and response messages together.

    Flags: 0x01 0x00
    A 16-bit value that contains various flags that indicate the type of query being made. 
    The 0x01 0x00 flags in this packet indicate a standard query with recursion desired.

    Question count: 0x00 0x01
    A 16-bit value that indicates the number of questions being asked in the query.
    In this case, there is only one question.

    Answer count: 0x00 0x00
    Authority count: 0x00 0x00
    Additional count: 0x00 0x00
    16-bit values that indicate the number of resource records in each section of the DNS message. 
    Since this is a query packet, all of these values are set to zero.

    Question: 0x0c (name length) 0x66 0x74 0x70 0x64 0x72 0x69 0x76 0x65 0x2e 0x6f 0x72 0x67 0x00 (name)
    A variable-length sequence of bytes that represents the question being asked in the query. 
    In this case, the question is ftpdrive.org and is encoded using DNS message compression.

    Type: 0x00 0x01
    A 16-bit value that indicates the type of resource record being queried for.
    In this case, it's a query for the address record of ftpdrive.org.

    Class: 0x00 0x01
    A 16-bit value that indicates the class of the query being made. 
    In this case, it's a query for an Internet address (IN).
    '''

    # Send the DNS query packet to the DNS server
    sock.sendto(dns_pkt, (dns_server_addr, 53))

    # Receive the response from the DNS server
    response_pkt, dns_server_addr = sock.recvfrom(1024)
    sock.close()
    return response_pkt

    # ask DNS Server to update the IP address of the api domain
def update_domain_ip(dns_server_addr, client_ip ,client_port):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((client_ip, client_port))
    sock.sendto("domain_update".encode(),(dns_server_addr, 53))
    sleep(0.1)
    sock.sendto("ftpdrive.org".encode(), (dns_server_addr, 53))
    sock.close()



def print_dns_reply(dns_reply):
    # Parse the DNS reply
    dns_msg = dns.message.from_wire(dns_reply)
    dns_answer = dns_msg.answer[0]
    dns_flags = dns_msg.flags

    #print the DNS header attributes
    print("\n    #DNS Header Attributes#")
    print("    ID:", dns_msg.id)
    print("    QR:", (dns_flags >> 15) & 0x1) 
    print("   ", dns_msg.opcode())
    print("    AA:", (dns_flags >> 10) & 0x1)
    print("    TC:", (dns_flags >> 9) & 0x1)
    print("    RD:", (dns_flags >> 8) & 0x1)
    print("    RA:", (dns_flags >> 7) & 0x1)
    print("     Z:", (dns_flags >> 4) & 0x1)
    print("   ", dns_msg.rcode())
    print("    QDCount:", len(dns_msg.question))
    print("    ANCount:", len(dns_msg.answer))
    print("    NSCount:", len(dns_msg.authority))
    print("    ARCount:", len(dns_msg.additional))

    # Print the DNS question attributes
    print("    Qname:", dns_msg.question[0].name.to_text())
    print("    Qtype:", dns.rdatatype.to_text(dns_msg.question[0].rdtype))
    print("    Qclass:", dns_msg.question[0].rdclass)

    # Print the Resource Records attributes
    print("\n    #Resource Records Attributes#")
    print("    Name:", dns_answer.name.to_text())
    print("    Type:", dns.rdatatype.to_text(dns_answer.rdtype))
    print("    Class:", dns_answer.rdclass)
    print("    TTL:", dns_answer.ttl)
    print("    Data: " + str(dns_answer[0]) + "\n")