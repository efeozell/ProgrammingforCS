import socket
import struct
import os
import sys
import datetime

IPLIST_PATH = "iplist.txt"

PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def cli_start_screen():
    print("╭─────────────╮")
    print("│  Efe Özel   │")
    print("╰─────────────╯")

def load_blacklist(path):
    if not os.path.exists(path):
        print(f"Error: '{path}' file not found")
        sys.exit(1)
    with open(path, "r") as f:
        ips = {line.strip() for line in f if line.strip()}
    if not ips:
        print(f"Warning: '{path}' is empt, no IPs will be monitored ")

    return ips

def parse_ip_header(packet):
    """Parse first 20 byte IP Header"""
    ip_header = packet[0:20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    header_length = ihl * 4

    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])

    return src_addr, dst_addr, protocol, header_length


def log_alert(direction, ip, protocol):
    proto_name = PROTOCOLS.get(protocol, f"PROTO-{protocol}")
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{ts}] ALERT: {direction} connection wityh blacklisted IP {ip} ({proto_name})"
    print(msg, flush=True)
    with open("ids_alerts.log", "a") as f:
        f.write(msg + "\n")


def main():
    if os.geteuid() != 0:
        print("Error: This script need to run with root privilege")

        sys.exit(1)

    monitored_ips = load_blacklist(IPLIST_PATH)
    print(f"[+] {len(monitored_ips)} IP loaded with blacklist")
    print("[+] Listening starting... (to exit CTRL + C)")

    #Listen Ethernet frames with AF_PACKET
    #0x0003 = ETH_P_ALL -> catches all protocols (TCP/UDP/ICMP)

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("Error: dont have privileges to open raw socket. try with sudo")
        sys.exit(1)
    except AttributeError:
        print("Error: AF_PACKET donst supported on this platform (just linux)")
        sys.exit(1)


    try:
        while True:
            packet, addr = s.recvfrom(65565)

            #Ethernet header 14 byre. Skip this and move IP header

            eth_header_len = 14
            eth_protocol = struct.unpack("!H", packet[12:14])[0]

            #0x0800 = IPv4
            if eth_protocol != 0x0800:
                continue

            ip_packet = packet[eth_header_len:]
            if len(ip_packet) < 20:
                continue

            src_addr, dst_addr, protocol, _ = parse_ip_header(ip_packet)


            if src_addr in monitored_ips:
                log_alert("Incoming", src_addr, protocol)
            if dst_addr in monitored_ips:
                log_alert("Outgoing", dst_addr, protocol)
    except KeyboardInterrupt:
        print("\n[+] Stopping...")
    finally:
        s.close()


if __name__ == "__main__":
    cli_start_screen()
    main()
