import socket, glob, json
import Net_Client
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP

port = 53
ip = ""

def change_zone_ip(new_ip_address, domain_name):
    zone_file = ''
    zonefiles = glob.glob('Zones/*.zone')
    for zone in zonefiles:
         if domain_name in zone:
            zone_file = zone
            break

    # Read zone file contents into a string variable
    with open(zone_file, 'r') as f:
        zone_str = f.read()

    # Parse zone file string into a dictionary object
    zone_dict = json.loads(zone_str)

    # Locate and update the "a" record for the domain name
    for record in zone_dict['a']:
        if record['name'] == '@':
            record['value'] = new_ip_address

    # Convert modified dictionary back into a JSON-formatted string
    zone_str = json.dumps(zone_dict, indent=4)

    # Write updated string back to the zone file
    with open(zone_file, 'w') as f:
        f.write(zone_str)

def loadZoneFiles():

    JsonZoneList = {}
    ZoneFiles = glob.glob('Zones/*.zone')
    for zone in ZoneFiles:
        with open(zone) as file_data:
            data = json.load(file_data)
            zoneName = data["$origin"]
            JsonZoneList[zoneName] = data
    return JsonZoneList

zone_files_data = loadZoneFiles()

def obtain_flags(flags):

    byte1 = bytes(flags[:1])

    QR = '1'

    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit))

    AA = '1'

    TC = '0'

    RD = '0'

    RA = '0'

    Z = '000'

    RCODE = '0000'

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

def obtain_question_domain(data):

    curr = 0
    anticipated_length = 0
    domain_str = ''
    domain_sections = []
    a = 0
    b = 0
    for byte in data:
        if curr == 1:
            if byte != 0:
                domain_str += chr(byte)
            a += 1
            if a == anticipated_length:
                domain_sections.append(domain_str)
                domain_str = ''
                curr = 0
                a = 0
            if byte == 0:
                domain_sections.append(domain_str)
                break
        else:
            curr = 1
            anticipated_length = byte
        b += 1

    q_type = data[b:b+2]

    return (domain_sections, q_type)

def getzone(domain):
    global zone_files_data
    zone_files_data = loadZoneFiles()
    zone_name = '.'.join(domain)
    if zone_name in zone_files_data:
        return zone_files_data[zone_name]
    else:
        return False

def get_recources(data):
    domain_sections, q_type = obtain_question_domain(data)
    qt = ''
    if q_type == b'\x00\x01':
        qt = 'a'

    zone = getzone(domain_sections)
    if zone:
        return (zone[qt], qt, domain_sections)
    else:
        return (False, '.'.join(domain_sections), qt)

def create_msg_question(domainname, record_type):
    q_bytes = b''

    for part in domainname:
        length = len(part)
        q_bytes += bytes([length])

        for char in part:
            q_bytes += ord(char).to_bytes(1, byteorder='big')

    if record_type == 'a':
        q_bytes += (1).to_bytes(2, byteorder='big')

    q_bytes += (1).to_bytes(2, byteorder='big')

    return q_bytes

def rectobytes(domainname, record_type, recttl, recval):

    rbytes = b'\xc0\x0c'

    if record_type == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if record_type == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes

def buildresponse(data):

    # Transaction ID
    Transaction_ID = data[:2]

    # Build flags
    Flags = obtain_flags(data[2:4])

    # Question count
    QDCOUNT = b'\x00\x01'

    # Answer count
    name_type = get_recources(data[12:])
    if not name_type[0]:
        print("No local Domain with the name: " + name_type[1])
        return ("No local Domain with the name: " + name_type[1]).encode()
        
    ANCOUNT = len(name_type[0]).to_bytes(2, byteorder='big')

    # Nameserver count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # Additonal count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = Transaction_ID+Flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT

    # Build body
    dnsbody = b''

    # obtain query answer for client 
    records, record_type, domainname = name_type

    dnsquestion = create_msg_question(domainname, record_type)

    for record in records:
        dnsbody += rectobytes(domainname, record_type, record["ttl"], record["value"])

    return dnsheader + dnsquestion + dnsbody

if __name__ == "__main__":
    print("Zone files loaded for domains: ")
    for zone in zone_files_data:
         print("    " + zone)
    
    # Get the local DNS IP address
    mac = Net_Client.get_mac()
    Net_Client.send_discover(mac)
    pkt = Net_Client.receive_offer()
    server_ip = pkt[0][IP].src
    offered_ip = pkt[0][BOOTP].yiaddr
    dns_ip = pkt[0][DHCP].options[4][1]
    print("Sending DHCP request for", dns_ip)
    Net_Client.send_request(mac, dns_ip, server_ip)
    print("Waiting for DHCP ACK")
    ack_pkt = Net_Client.receive_acknowledge()
    if ack_pkt != "Timeout":
        print("DHCP ACK received: ", ack_pkt[0][BOOTP].yiaddr)
    else:
        print("DHCP ACK not received")
        exit(1)
    

    # Start the DNS server
    ip = dns_ip
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind((ip, port))

    print("DNS server started on port " + str(port) + " and IP " + ip)
    while 1:
        data, addr = sock.recvfrom(512)
        if data == "domain_update".encode():
            domain_name, addr = sock.recvfrom(512)
            zonefiles = glob.glob('Zones/*.zone')
            for zone in zonefiles:
                if domain_name.decode() in zone:
                    change_zone_ip(addr[0], domain_name.decode())
                    print("Updated zone file for domain: " + domain_name.decode())
                    break
                
        else:
            r = buildresponse(data)
            sock.sendto(r, addr)
            print("Sent response to", addr)

