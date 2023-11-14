import Net_Client
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP
import unittest
import socket
import dns.message
import dns.rdatatype

Port = 2000

def get_anticipated_server_ip():
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        router_ip = s.getsockname()[0] 
        router_ip_prefix = router_ip.split(".")[:-2]
        server_ip = ".".join(router_ip_prefix) + "." + str(int(router_ip.split(".")[2]) + 1)  + ".1"
    return server_ip

class TestClient(unittest.TestCase):
     def test_dhcp_dns(self):
        # check if the DHCP server is sniffing, can send a proper offer packet, and runs on an anticipated IP
        mac = Net_Client.get_mac()
        Net_Client.send_discover(mac)
        pkt = Net_Client.receive_offer()
        server_ip = get_anticipated_server_ip()
        offered_ip = pkt[0][BOOTP].yiaddr
        self.assertEqual(pkt[0][IP].src, server_ip)

        # check if the DHCP client can send a proper request packet and receive an ACK packet
        Net_Client.send_request(mac, offered_ip, server_ip)
        print("Waiting for DHCP ACK")
        ack_pkt = Net_Client.receive_acknowledge()
        self.assertEqual(ack_pkt[0][BOOTP].yiaddr, offered_ip)

        # check if the dns server is listening and can send a proper reply packet with the domain name we asked for
        dns_ip = pkt[0][DHCP].options[4][1]
        # Send a DNS query for ftpdrive.org
        dns_reply = Net_Client.send_DNS_query(dns_ip, offered_ip, Port)
        print("Received DNS reply.")
        dns_msg = dns.message.from_wire(dns_reply)
        # Net_Client.print_dns_reply(dns_reply) # For printing the DNS reply
        domain_name = dns_msg.answer[0].name.to_text()
        self.assertEqual(domain_name, "ftpdrive\.org.")

if __name__ == '__main__':
    unittest.main()

