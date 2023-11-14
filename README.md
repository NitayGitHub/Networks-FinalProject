# Networks Final Project

## FTP (File Transfer Protocol)

**What is FTP?**
FTP (File Transfer Protocol) is a network protocol that transfers files between a client and a server. The server allows users to upload and download various types of files, including images, text files, and music.

**Why is FTP useful?**
FTP serves multiple purposes:
1. **Backup:** Uploading files to back them up in another location.
2. **File Transfer:** Facilitating easy and quick file transfers between computers.

**How does FTP work?**
- A user creates an account on the FTP server to use FTP.
- The server stores uploaded files in a designated folder.
- Users can download files they previously uploaded.
- The interaction involves the server permitting to download of files at any given moment.

## DHCP (Dynamic Host Configuration Protocol) Server

DHCP is a client and server protocol that automates the allocation of IP addresses and related information (subnet mask, default gateway) to devices on a network.

**DHCP Workflow:**
1. The DHCP server listens on port 67.
2. When a device seeks an IP address, it sends a discovery message to port 67.
3. The DHCP server responds with an IP address and additional information.
4. The client confirms readiness and requests permission to use the assigned IP.
5. If accepted, the server sends an acknowledgment message.

## DNS (Domain Name System) Server

DNS servers handle DNS queries, translating user-friendly domain names into IP addresses for computers to communicate effectively.

**Primary DNS Server:**
A primary DNS server is the first contact point for a browser seeking a site. It contains the controlling zone file, including DNS information, IP addresses, and administrative contact details.

**Domain IP Lookup Process:**
- Contact the top-level server for the last part of the domain.
- Iteratively move through servers from right to left in the domain address.
- Reach the server responsible for the domain to obtain the requested IP.

*Note: The domain IP lookup is an iterative process mostly handled by internet service provider's servers.*

## State diagram of the program
![image](https://github.com/NitayGitHub/Networks-FinalProject/assets/118196923/d9c2c0f6-f389-4bb4-a72a-078798532e73)

