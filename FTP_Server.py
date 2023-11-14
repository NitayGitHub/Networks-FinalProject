import socket
import time
import os
import Net_Client
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP
import json, glob


def checkFiles(cusername):
    directory = "MyUsers//" + cusername
    files = []
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            files.append(filename)
    files.sort()
    returnedListFile = b""
    for fileByte in files:
        returnedListFile += fileByte.encode() + ':'.encode()
    returnedListFile = returnedListFile[:-1]
    return returnedListFile


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
    sock.sendto(packeta, client_address)
    while not suc:
        try:
            checkSeq, addressF = sock.recvfrom(4)
            suc = True
        except TimeoutError:
            print("Packet was lost")
            sock.sendto(packeta, client_address)
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
    
    Net_Client.update_domain_ip(dns_ip, offered_ip ,30251)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (offered_ip, 30251)
    client_address = None
    sock.bind(server_address)
    packet_size = 64004
    while True:
        print("start")
        check_seq = 0
        got_seq = -1
        flag = False
        while True:
            while not flag:
                try:
                    data, address = sock.recvfrom(64000)
                    client_address = address
                    flag = True
                except TimeoutError:
                    flag = False
            print(data)
            got_seq = data[:4]
            got_seq = int.from_bytes(got_seq, 'big')
            action = "".join(chr(i) for i in data).split(':')[1]
            fileName = "".join(chr(i) for i in data).split(':')[2]
            username = "".join(chr(i) for i in data).split(':')[3]
            if got_seq == check_seq and action != '3':
                sock.sendto(check_seq.to_bytes(4, 'big'), client_address)
                check_seq += 1
                break
            if action == '3':
                break
        match action:
            case '1':
                sock.settimeout(1)
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
                        sock.sendto(check_seq.to_bytes(4, 'big'), client_address)
                        check_seq += 1
                    filepart = filepart[4:]
                    fileBuffer[got_seq] = filepart
                for part in fileBuffer:
                    if username.encode() not in part:
                        file += part
                fp = open("MyUsers" + r"/" + username + r"/" + fileName, "wb")
                fp.write(file)
                fp.close()
                check_seq -= 1
            case '2':
                sock.settimeout(0.1)
                fp = open("MyUsers" + "//" + username + "//" + fileName, "rb+")
                seq_num = 0
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
            case '3':
                print("start3:")
                sock.sendto(checkFiles(username), client_address)
            case _:
                print("")
                break
    sock.close()
