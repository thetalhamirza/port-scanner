import os
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ICMP, IP, sr1, TCP, sr
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from colorama import init
from termcolor import colored

init()

print_lock = Lock()

def ping(host):
    response = sr1(IP(dst=str(host))/ICMP(), timeout=1, verbose=0)
    if response is not None:
        return str(host)
    return None

def ping_sweep(network, netmask):
    live_hosts = []

    # num_threads = os.cpu_count()
    num_threads = threads

    hosts = list(ip_network(network + '/' + netmask).hosts())
    total_hosts = len(hosts)

    with ThreadPoolExecutor(num_threads) as executor:
        futures = {executor.submit(ping, host): host for host in hosts}
        for i, future in enumerate(as_completed(futures), start=1):
            host = futures[future]
            result = future.result()
            with print_lock:
                print(colored(f"[+] Scanning {i}/{total_hosts}", "light_blue"), end="\r")
                if result is not None:
                    print(colored(f"\n\n[>] Host {host} is online.\n", "green"))
                    live_hosts.append(result)
        for _ in range(100):
            print(colored("-", "blue"), end="")
        print(colored("\nOnline hosts: ", "green"))
        for host in live_hosts:
            print(colored(f"[>] {host}", "green"))
        print("")
        for _ in range(100):
            print(colored("-", "blue"), end="")
        print("")
    return live_hosts


def scan_port(args):
    ip, port = args
    response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
    if response is not None and response[TCP].flags == "SA":
        return port
    return None

def port_scan(ip, ports):
    open_ports = []

    # num_threads = os.cpu_count()
    num_threads = threads
    total_ports = len(ports)

    with ThreadPoolExecutor(num_threads) as executor:
        futures = {executor.submit(scan_port, (ip, port)): port for port in ports}
        for i, future in enumerate(as_completed(futures), start=1):
            port = futures[future]
            result = future.result()
            with print_lock:
                print(colored(f"[+] Scanning {ip}: {i}/{total_ports}", "light_blue"), end="\r")
                if result is not None:
                    print(colored(f"\n[>] Port {port} is open on host {ip}\n", "green"))
                    open_ports.append(result)
        print("")
        for _ in range(100):
            print(colored("-", "blue"), end="")            
        print("")
    return open_ports

def get_live_hosts_and_ports(network, netmask):
    live_hosts = ping_sweep(network, netmask)

    host_port_mapping = {}
    # Define the common ports list
    common_ports = {21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 3306, 
                3389, 5900, 8080, 8443, 9200, 11211}

    # Merge with the range of 1-1023
    ports = set(range(1, 1024)) | common_ports  # Using set union to avoid duplicates

    # Convert back to a sorted list for ordered scanning
    ports = sorted(ports)
    for host in live_hosts:
        open_ports = port_scan(host, ports)
        host_port_mapping[host] = open_ports

    return host_port_mapping

def main():
    global threads
    network = sys.argv[1]
    netmask = sys.argv[2]
    if len(sys.argv) == 4:
        threads = int(sys.argv[3])
        print(colored(f"\n[+] Threads set: {threads}\n", "light_blue"))
    else:
        threads = 50
        print(colored(f"\n[+] Default threads set: {threads}\n", "light_blue"))

    host_port_mapping = get_live_hosts_and_ports(network, netmask)
    print("\n\n")
    for host, open_ports in host_port_mapping.items():
        print(colored(f"--> Host {host} has the following open ports: {open_ports}", "light_green"))


if __name__ == "__main__":
    main()