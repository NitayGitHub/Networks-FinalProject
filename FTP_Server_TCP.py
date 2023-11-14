import socket
import os
from time import sleep
import Net_Client
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP

Port = 30251

def checkFiles(cusername):
    directory = "MyUsers//" + cusername
    files = []
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            files.append(filename)
    files.sort()
    sleep(0.5)
    rlist = ""
    for file in files:
        rlist += "     " + file + "\n"
    return rlist.encode()

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
    
    Net_Client.update_domain_ip(dns_ip, offered_ip ,Port)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (offered_ip, Port)

    sock.bind(server_address)
    sock.listen(3)
    print("Listening...")
    packet_size = 64000
    while True:
        client_sock, address = sock.accept()
        print("Connected")
        while True:
            
            data = client_sock.recv(packet_size)
            if not data:
                print("Timeout. Closing...")
                client_sock.close()
                exit(1)

            action_data = data.decode().split(':')
            print(action_data)
            action = action_data[0]
            fileName = action_data[1]
            username = action_data[2]
            
            match action:
                case '1':
                    client_sock.sendall("ACK".encode())
                    with open("MyUsers/" + username + "/" + fileName, "wb") as fp:
                        while True:
                            file_data = client_sock.recv(packet_size)
                            if  file_data == "EOF".encode():
                                print("File Uploaded.")
                                break
                            fp.write(file_data)
                    
                case '2':
                    if os.path.exists("MyUsers/" + username + "/" + fileName):
                        client_sock.sendall("ACK".encode())
                        sleep(1)
                        file_size = os.path.getsize("MyUsers/" + username + "/" + fileName)
                        middle_size = int(file_size / 2)
                        data_sum = 0
                        pkt_size = packet_size
                        stp_mid = client_sock.recv(packet_size)
                        stop_dec = 0
                        if stp_mid.decode() == "STOP":
                            print("File transfer will stop in middle.")
                            stop_dec = 1
                            
                        with open("MyUsers/" + username + "/" + fileName, "rb") as fp:
                            while True:
                                if data_sum == middle_size and stop_dec:
                                    print("File upload stopped in : " + str(data_sum) + " bytes")
                                    client_sock.sendall("STOPED".encode())
                                    usr_dec = client_sock.recv(packet_size).decode()
                                    if usr_dec == "STOP":
                                        sleep(0.5)
                                        pkt_size = packet_size
                                        break
                                    pkt_size = packet_size
                                    stop_dec = 0
                                elif (data_sum + pkt_size) > middle_size and stop_dec:
                                    pkt_size = middle_size - data_sum
                                    print (pkt_size)

                                file_data = fp.read(pkt_size)
                                data_sum += len(file_data)
                                sleep(0.1)
                                if not file_data:
                                    sleep(1)
                                    client_sock.sendall("EOF".encode())
                                    print("File Sent.")
                                    break
                                client_sock.sendall(file_data)
                    else:
                        client_sock.sendall("NACK".encode())
                
                case '3':
                    client_sock.sendall("ACK".encode())
                    sleep(0.5)
                    client_sock.sendall(checkFiles(username))
                    print("List Sent.")

                case '4':
                    if os.path.exists("MyUsers/" + username):
                        
                        client_sock.sendall("ACK".encode())
                        with open("MyUsers/" + username + "/" + fileName, "wb") as fp:
                            while True:
                                file_data = client_sock.recv(packet_size)
                                if  file_data == "EOF".encode():
                                    print("File Uploaded.")
                                    break
                                fp.write(file_data)
                    
                    else:
                        client_sock.sendall("NACK".encode())
                
                case '5':
                    if os.listdir("MyUsers/" + username):
                        client_sock.sendall("ACK".encode())
                        for file in os.listdir("MyUsers/" + username):
                            file_path = os.path.join("MyUsers/" + username, file)
                            os.remove(file_path)
                        print("Dirctory has been cleand")
                    else:
                        client_sock.sendall("NACK".encode())

                case _:
                    client_sock.sendall("NACK".encode())
                    