import os
import socket
from time import sleep
import Net_Client
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP
import dns.message
import dns.rdatatype

Port = 20599

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
    dns_reply = Net_Client.send_DNS_query(dns_ip, offered_ip, Port)
    dns_msg = dns.message.from_wire(dns_reply)
    # Net_Client.print_dns_reply(dns_reply) # For printing the DNS reply
    api_ip = str(dns_msg.answer[0][0])
    print("Received DNS reply. API IP: ", api_ip)
    
    answer = input("Enter 1 to register or 2 to log in: ")
    while answer != '1' and answer != '2':
        answer = input("You wrote somthing wrong.\nEnter 1 to register or 2 to log in: ")
    returnAnswer = 1
    while returnAnswer:
        if answer == '1':
             regAns = False
             while not regAns:
                 username = input("Enter your username: ")
                 password = input("Enter your password: ")
                 regAns = register(username, password)
                 returnAnswer = 0
        if answer == '2':
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            loginFlag = login(username, password)
            if loginFlag:
                returnAnswer = 0
                print("login succeeded\n")
                break
            answer = input("login unsuccessful. Please try again.\nEnter 1 to register or 2 to log in: ")
            while answer != '1' and answer != '2':
                answer = input("You wrote somthing wrong.\nEnter 1 to register or 2 to log in: ")
            

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    
    sock.bind((offered_ip, Port))
    sock.settimeout(5)
    packet_size = 64000
    server_port = 30251
    server_address = (api_ip, server_port)

    sock.connect(server_address)
    keepLoop = 1
    while keepLoop:
        action = input(
            "Choose an action:\n1. Upload a file to the FTP server\n2. Download a file from the FTP server\n"
            "3. View all the files you can download\n4. send a file to a friend\n5. Empty Directory\n6. To exit.\n")
        match action:
            case '1':
                while True:
                    fileName = input("Write the name of the file you want to upload: ")
                    if os.path.exists(fileName):
                        break
                    else:
                        print("File does not exist. try again")
                
                data_packet = action + ':' + fileName + ':' + username
                sock.sendall(data_packet.encode())
                answer = (sock.recv(packet_size)).decode()
                print("\nServer answer:", answer)
                if answer == "ACK":
                    print("File transfer started")
                    print("Uploading " + os.path.basename(fileName) + "...")
                    file_size = os.path.getsize(fileName)
                    middle_size = int(file_size / 2)
                    print("File size: " + str(file_size) + " bytes")
                    data_sum = 0
                    usr_input = int(input("Do you want to stop middle packet upload?\nno: 0, yes: any.\n"))
                    pkt_size = packet_size
                    
                    with open(fileName, "rb") as fp:
                        while True:
                            if data_sum == middle_size and usr_input:
                                print("File upload stopped in : " + str(data_sum) + " bytes")
                                usr_dec = input("Do you want to continue? no: 0, yes: any.\n")
                                if not int(usr_dec):
                                    pkt_size = packet_size
                                    sock.sendall("EOF".encode())
                                    break
                                pkt_size = packet_size
                                usr_input = 0
                            elif (data_sum + pkt_size) > middle_size and usr_input:
                                pkt_size = middle_size - data_sum
                                print (pkt_size)
                            
                            file_data = fp.read(pkt_size)
                            data_sum += len(file_data)
                            if not file_data:
                                sleep(1)
                                sock.sendall("EOF".encode())
                                break
                            sock.sendall(file_data)
                    print("File uploaded successfully.\n")

                else:
                    print("No such action in server.\n")
                
            case '2':
                fileName = input("Write the name of the file you want to download: ")
                data_packet = action + ':' + fileName + ':' + username
                sock.sendall(data_packet.encode())
                answer = sock.recv(packet_size).decode()
                print("\nServer answer:", answer)
                if answer == "ACK":
                    usr_input = int(input("Do you want to stop middle packet upload?\nno: 0, yes: any.\n"))
                    if usr_input:
                        sock.sendall("STOP".encode())
                    else:
                        sock.sendall("CONT".encode())
                    print("File download started")
                    with open(fileName, "wb") as fp:
                        while True:
                            file_data = sock.recv(packet_size)
                            if  file_data == "STOPED".encode():
                                usr_dec = input("Do you want to continue? no: 0, yes: any.\n")
                                if not int(usr_dec):
                                    sock.sendall("STOP".encode())
                                    sleep(0.5)
                                    print("File downloaded until mid.")
                                    break
                                sock.sendall("CONT".encode())
                                
                            if  file_data == "EOF".encode():
                                print("File downloaded.")
                                break
                            fp.write(file_data)

                else:
                    print("No such action or file in server.\n")

            case '3':
                data_packet = action + ':' + '' + ':' + username
                sock.sendall(data_packet.encode())
                answer = sock.recv(packet_size).decode()
                print("\nServer answer: " + answer)
                if answer == "ACK":
                    fileList, address = sock.recvfrom(packet_size)
                    fileList = fileList.decode()
                    print("These are the files you can download:")
                    print(fileList)
                    
                else:
                    print("No such action in server.\n")

            case '4':
                while True:
                    fileName = input("Write the name of the file you want to upload: ")
                    if os.path.exists(fileName):
                        break
                    else:
                        print("File does not exist. try again")
                friendusr = input("Write the name of the user you want to sendall the file to: ")
                data_packet = action + ':' + fileName + ':' + friendusr
                sock.sendall(data_packet.encode())
                answer = (sock.recv(packet_size)).decode()
                print("\nServer answer:", answer)
                if answer == "ACK":
                    print("File transfer started")
                    print("sendalling " + os.path.basename(fileName) + "...")
                    file_size = os.path.getsize(fileName)
                    print("File size: " + str(file_size) + " bytes")
                    
                    with open(fileName, "rb") as fp:
                        while True:
                            file_data = fp.read(packet_size)
                            if not file_data:
                                sleep(1)
                                sock.sendall("EOF".encode())
                                break
                            sock.sendall(file_data)
                    print("File uploaded successfully.\n")
                
                else:
                    print("No such action or user in server.\n")
            
            case '5':
                data_packet = action + ':' + '' + ':' + username
                sock.sendall(data_packet.encode())
                answer = (sock.recv(packet_size)).decode()
                print("\nServer answer: " + answer)
                if answer == "ACK":
                    print("Directory emptied.")
                else:
                    print("No such action or dir already empty in server.\n")

            case '6':
                keepLoop = 0
            
            case _:
                print("You entered an invalid number.")
                
    sock.close()
