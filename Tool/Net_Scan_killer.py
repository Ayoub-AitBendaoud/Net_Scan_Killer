import pyfiglet
from scapy.all import ARP, Ether, srp
import argparse
import socket
import time
import termcolor

ascii_banner = pyfiglet.figlet_format("Net_Scan_killer", font="slant")
subtitle = "Network Scanner Killer : tool\nDevices, open ports (OS detection - limited)"
author_tag = "Build By Ayoub AitBendaoud"
print(ascii_banner)
print(" " * 35 + author_tag)
print(subtitle)
print()
platf_ver = (
    "Version  : 1.0.0\n"
    "Github   : https://github.com/Ayoub-AitBendaoud?tab=repositories\n"
    "Youtube  : https://www.youtube.com/@Ayoub_Aitbendaoud\n"
    "Linkedin : https://www.linkedin.com/in/ayoub-ait-bendaoud-b03025243/"
)
print(platf_ver)
print()
############################################**@Ayoub_Aitbendaoud**############################################
def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scan killer tool")
    parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface to use")
    parser.add_argument("-r", "--range", type=str, required=True, help="IP range to scan")
    parser.add_argument("-f", "--fast", action="store_true", help="Enable fast mode to scan automatically and continuously")
    args = parser.parse_args()
    return args

def scan(ip_range, interface):
    arp_request = ARP(pdst=ip_range)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = ether_frame / arp_request

    result = srp(arp_request_packet, iface=interface, timeout=2, verbose=False)[0]

    clients = []
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((received.psrc, 139))
            if result == 0:
                os = "Windows (Possible)"
            else:
                if "linux" in hostname.lower():
                    os = "Linux (Possible)"
                else:
                    os = "Unknown"
            s.close()
        except Exception:
            os = "Unknown"

        clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'hostname': hostname, 'os': os})
    return clients
############################################**@Ayoub_Aitbendaoud**############################################
def print_result(clients):
    print("IP Address\t\tMAC Address\t\tHostname\t\tOS")
    print("-" * 80)
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}\t\t{client['hostname']}\t\t{client['os']}")

def scan_ports(target, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((target, port))
            open_ports.append(port)
            sock.close()
        except socket.timeout:
            pass
        except socket.error:
            pass
    return open_ports

def print_port_results(target, open_ports):
    if open_ports:
        print(termcolor.colored(f"Open Ports on {target}:", 'cyan'))
        for port in open_ports:
            print(termcolor.colored(f"[+] Port {port} is open", 'cyan'))
    else:
        print(termcolor.colored(f"No open ports found on {target}", 'red'))

if __name__ == "__main__":
    args = get_arguments()
    common_ports = [20, 21, 22, 23, 25, 42, 43, 53, 67, 79, 80, 107, 109, 115, 123, 137, 143, 153, 179, 443, 445, 500, 587, 660, 902, 903, 3020, 3006, 3007, 3389, 4444, 5000, 5555]

    while True:
        scanned_clients = scan(args.range, args.interface)
        print_result(scanned_clients)
        
        for client in scanned_clients:
            open_ports = scan_ports(client['ip'], common_ports)
            print_port_results(client['ip'], open_ports)
        
        if not args.fast:
            break
        time.sleep(1)
############################################**@Ayoub_Aitbendaoud**############################################
#You are welcome any feedback is greatly appreciated as I try to improve and add more features to this tool.**
#linkedin & YOutube & github : @Ayoub_aitbendaoud