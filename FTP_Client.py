import os
import socket
import time
import Net_Client
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP
import dns.message
import dns.rdatatype


def clean():
    for file in os.listdir("MyUsers"):
        file_path = os.path.join("MyUsers", file)
        os.rmdir(file_path)
    print("All directories have been cleand")


def register(rusername, rpassword):
    fptr = open("users_and_passwords", "a+")
    for line in fptr:
        if rusername in line:
            words = line.split(':')
            if rusername == words[0]:
                return False
    fptr.write(rusername + ':' + rpassword + "\n")
    fptr.close()
    print(f"User {rusername} added successfully.")
    path = os.path.join("MyUsers", rusername)
    if not os.path.exists(path):
        os.mkdir(path)
    return True


def login(lusername, lpassword):
    with open("users_and_passwords", 'r') as fileuap:
        for line in fileuap:
            if lusername in line:
                words = line.split(':')
                if lpassword + "\n" == words[1]:
                    return True
    return False


def try_send_pack(packeta):
    suc = False
    sock.sendto(packeta, server_address)
    while not suc:
        try:
            checkSeq, addressF = sock.recvfrom(packet_size)
            suc = True
        except TimeoutError:
            print("Packet was lost")
            sock.sendto(packeta, server_address)
            suc = False
    return checkSeq


def try_send_ack(packeta):
    suc = False
    sock.sendto(packeta, server_address)
    while not suc:
        try:
            checkSeq, addressF = sock.recvfrom(4)
            suc = True
        except TimeoutError:
            print("Packet was lost")
            sock.sendto(packeta, server_address)
            suc = False
    return int.from_bytes(checkSeq, 'big')


if __name__ == '__main__':
    # Get a local IP address
    mac = Net_Client.get_mac()
    Net_Client.send_discover(mac)
    pkt = Net_Client.receive_offer()
    server_ip = pkt[0][IP].src
    offered_ip = pkt[0][BOOTP].yiaddr
    dns_ip = pkt[0][DHCP].options[4][1]
    print("DNS IP: ", dns_ip)
    print("Sending DHCP request for", offered_ip)
    Net_Client.send_request(mac, offered_ip, server_ip)
    print("Waiting for DHCP ACK")
    ack_pkt = Net_Client.receive_acknowledge()
    if ack_pkt != "Timeout":
        print("DHCP ACK received: ", ack_pkt[0][BOOTP].yiaddr)
    else:
        print("Timeout: No DHCP ACK received.")
        exit(1)

    # Send a DNS query for ftpdrive.org
    dns_reply = Net_Client.send_DNS_query(dns_ip, offered_ip, 20599)
    dns_msg = dns.message.from_wire(dns_reply)
    api_ip = str(dns_msg.answer[0][0])
    print("Received DNS reply. API IP: ", api_ip)

    answer = input("Are you logged in or you need to register?\n1 for register and 2 for log in: \n")
    while answer != '1' and answer != '2':
        answer = input("You wrote somthing wrong.\n1 for register and 2 for log in: \n")
    returnAnswer = -1
    while returnAnswer != 0:
        if answer == '1':
            regAns = False
            while not regAns:
                username = input("Enter your username: ")
                password = input("enter your password: ")
                regAns = register(username, password)
                returnAnswer = 0
        if answer == '2':
            username = input("Enter your username: ")
            password = input("enter your password: ")
            loginFlag = login(username, password)
            if loginFlag:
                returnAnswer = 0
                print("login succeeded")
                break
            print("login unsuccessful. Please try again. If you want to register press 1 if you want to try "
                  "login again press 2")
            answer = input()
    action = input("choose an action:\n1. Upload a file to the FTP server\n2. Download a file from the FTP server\n"
                   "3. View all the files you can download\nAny other character to exit\n")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    seq_num = 0
    packet_size = 64004
    server_address = (api_ip, 30251)
    client_address = (offered_ip, 20599)
    sock.bind(client_address)
    cont = '1'
    opened = 0
    while cont == '1':
        match action:
            case '1':
                sock.settimeout(0.1)
                while opened == 0:
                    fileName = input("Write the name of the file you want to upload: ")
                    try:
                        opened = 1
                        fp = open(fileName, "rb")
                    except EnvironmentError:
                        print("File cannot be opend. try again")
                        opened = 0
                opened = 0
                data_packet = ':' + action + ':' + fileName + ':' + username
                seq_num = 0
                packet = seq_num.to_bytes(4, byteorder='big') + data_packet.encode()
                print("this is the data and ack:")
                print(packet)
                seq_num_check = try_send_ack(packet)
                seq_num += 1
                buffer = fp.read()
                fp.close()
                k = int(buffer.__sizeof__() / (packet_size - 4))
                mod = int(buffer.__sizeof__() % (packet_size - 4))
                i = 0
                while i <= k:
                    sendBuf = buffer[i * (packet_size - 4):(i + 1) * (packet_size - 4)]
                    packet = seq_num.to_bytes(4, byteorder='big') + sendBuf
                    seq_num_check = try_send_ack(packet)
                    if seq_num == seq_num_check:
                        i += 1
                        seq_num += 1
                sendBuf = buffer[(i + 1) * (packet_size - 4):(i + 1) * (packet_size - 4) + mod]
                packet = seq_num.to_bytes(4, byteorder='big') + sendBuf
                seq_num_check = try_send_ack(packet)
                time.sleep(1)
                seq_num = 0
                print("File Uploaded successfully!")

            case '2':
                sock.settimeout(1)
                fileName = input("Write the name of the file you want to download: ")
                data_packet = ':' + action + ':' + fileName + ':' + username
                packet = int.to_bytes(seq_num, 4, 'big') + data_packet.encode()
                try_send_pack(packet)
                check_seq = 1
                fileBuffer = [b''] * 1000
                for i in range(1000):
                    fileBuffer[i] = b''
                file = b''
                while True:
                    try:
                        filepart, address = sock.recvfrom(packet_size)
                    except TimeoutError:
                        filepart = "EOF".encode()
                        break
                    got_seq = int.from_bytes(filepart[:4], 'big')
                    if got_seq + 1 == check_seq:
                        check_seq -= 1
                    if got_seq == check_seq:
                        sock.sendto(check_seq.to_bytes(4, 'big'), server_address)
                        check_seq += 1
                    filepart = filepart[4:]
                    fileBuffer[got_seq] = filepart
                for part in fileBuffer:
                    if username.encode() not in part:
                        file += part
                fp = open(fileName, "wb")
                fp.write(file)
                fp.close()
                seq_num = 0
                print("File downloaded successfully!")

            case '3':
                print("start 3")
                sock.settimeout(0.1)
                fileName = ""
                data_packet = ':' + action + ':' + fileName + ':' + username
                packet = int.to_bytes(seq_num, 4, 'big') + data_packet.encode()
                fileList = try_send_pack(packet).decode()
                print("this is all the files you can download sorted by name: ")
                print(fileList.split(':'))
                seq_num = 0
            case _:
                print("Are you sure you want to exit?")
        cont = input("If you want to make more actions press 1. if you want to exit press any other key.\n ")
        if cont != '1':
            break
        action = input(
            "choose an action:\n1. Upload a file to the FTP server\n2. Download a file from the FTP server\n"
            "3. View all the files you can download\n4. Send a file to a friend\n")
    sock.close()
