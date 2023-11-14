from time import sleep
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether, ARP
from pyroute2 import IPRoute
import random


requested_ips = {}
assigned_ips = {}
domain_ip = ""
server_prefix = ""
server_ip = ""

def get_router_prefix():
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        router_ip = s.getsockname()[0] 
        router_ip_prefix = router_ip.split(".")[:-2]
        router_ip_prefix = ".".join(router_ip_prefix) + "." + str(int(router_ip.split(".")[2]) + 1)
    return router_ip_prefix

server_prefix = get_router_prefix()
server_ip = server_prefix + ".1"

# Function to check if an IP address is in use
def ip_in_use(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=ip)
    arp_response = srp1(arp_request, timeout=1, verbose=0)
    if arp_response is not None:
        return True
    else:
        return False

# Create random IP address
def get_random_ip():
    global server_prefix
    ip = IPRoute()

    # Get the index of the network interface you want to assign the IP address to
    iface_index = ip.link_lookup(ifname=conf.iface)[0]

    # Create a new IP address object
    address = server_prefix + "." + str(random.randint(2, 254))

    while ip_in_use(address) or (assigned_ips and address in assigned_ips.values()):
            print(f"Requested IP {address} is already in use, offering diffrent IP")
            address = server_prefix + "." + str(random.randint(2, 254))
    
    
    ip_addr = {'family':socket.AF_INET, 'prefixlen':24, 'addr': address}

    # Add the new IP address to the network interface
    ip.addr('add', index=iface_index, address=ip_addr['addr'], mask=ip_addr['prefixlen'], family=ip_addr['family'])
    
    return address

# A function to handle sniffed DHCP packets
def handle_dhcp_request(pkt):
    # Check if the packet is a DHCP discovery message
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        print("DHCP Discover received")
        
        client_mac = pkt[Ether].src
        
        # Generate a random IP address to offer client
        random_ip = get_random_ip()
        
        requested_ips[client_mac] = random_ip
        offer = Ether(src=get_if_hwaddr(conf.iface), dst=client_mac)/ \
            IP(src=server_ip, dst=random_ip)/ \
            UDP(sport=67, dport=68)/ \
            BOOTP(op=2, yiaddr=random_ip, siaddr=server_ip, giaddr="0.0.0.0", xid=pkt[BOOTP].xid)/ \
            DHCP(options=[("message-type", "offer"),
                           ("subnet_mask", "255.255.255.0"),
                           ("router", server_ip),
                           ("lease_time", 86400),
                           ("name_server", domain_ip),
                           "end"])

        # Send offer to client
        sleep(1)
        sendp(offer, iface=conf.iface)
        print(f"DHCP Offer sent with IP: {random_ip}")

    # Check if the packet is a DHCP request message
    elif DHCP in pkt and pkt[DHCP].options[0][1] == 3:
        print("DHCP Request received for IP: " + pkt[DHCP].options[2][1])
        client_mac = pkt[Ether].src
        requested_ip = pkt[DHCP].options[2][1]
        # Check if the requested IP is the same as the one offered
        if client_mac in requested_ips and requested_ip == requested_ips[client_mac]:
            ack = Ether(src=get_if_hwaddr(conf.iface), dst=client_mac)/ \
                IP(src=server_ip, dst=requested_ip)/ \
                UDP(sport=67, dport=68)/ \
                BOOTP(op=2, yiaddr=requested_ip, siaddr=server_ip, giaddr="0.0.0.0", xid=pkt[BOOTP].xid)/ \
                DHCP(options=[("message-type", "ack"),
                                ("subnet_mask", "255.255.255.0"),
                                ("router", server_ip),
                                ("lease_time", 86400),
                                ("name_server", domain_ip),
                                "end"])

            # Send ack to client
            sleep(1)
            sendp(ack, iface=conf.iface)
            print(f"DHCP ACK sent to {client_mac} with IP: {requested_ip}")
            requested_ips.pop(client_mac)
            assigned_ips[client_mac] = requested_ip

        # Check if the requested IP is the same as the DNS server IP
        elif client_mac in requested_ips and requested_ip == domain_ip and requested_ip not in assigned_ips.values():
            ack = Ether(src=get_if_hwaddr(conf.iface), dst=client_mac)/ \
                IP(src=server_ip, dst=requested_ip)/ \
                UDP(sport=67, dport=68)/ \
                BOOTP(op=2, yiaddr=requested_ip, siaddr=server_ip, giaddr="0.0.0.0", xid=pkt[BOOTP].xid)/ \
                DHCP(options=[("message-type", "ack"),
                                ("subnet_mask", "255.255.255.0"),
                                ("router", server_ip),
                                ("lease_time", 86400),
                                ("name_server", domain_ip),
                                "end"])
            
            # Send ack to client
            sleep(1)
            sendp(ack, iface=conf.iface)
            print(f"DHCP ACK sent to {client_mac} with domain IP: {requested_ip}")
            requested_ips.pop(client_mac)
            assigned_ips[client_mac] = requested_ip
        else:
            print(f"Requested IP {requested_ip} was taken or not offered by the DHCP server")
        

# Create and save an IP address for the DNS server
domain_ip = get_random_ip()

# Sniff discovery and request packets on port 67 and 68
sniff_filter = "udp and (port 67 or 68)"

# Begin sniffing for DHCP packets
print("DHCP Server started.")
print(f"DHCP Server IP: {server_ip}. DNS Server IP: {domain_ip}.")
sniff(filter=sniff_filter, prn=handle_dhcp_request)

