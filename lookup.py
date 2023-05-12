import os
import sys
from ipaddress import ip_network, ip_address
from ipwhois import IPWhois

def read_ip_addresses(file_path):
    with open(file_path, 'r') as file:
        ips = [line.strip() for line in file.readlines()]
    return ips

def main():
    file_path = input("Please enter the path to the file containing the list of IP addresses: ").strip()

    if not os.path.exists(file_path):
        print(f"File '{file_path}' not found. Please enter a valid file path.")
        sys.exit(1)

    ip_list = read_ip_addresses(file_path)

    print(f"{'IP/CIDR':<18} {'Range':<35} {'ASN':<10} {'Owner'}")

    for ip_or_cidr in ip_list:
        try:
            if '/' in ip_or_cidr:
                network = ip_network(ip_or_cidr, strict=False)
                lookup_ip = str(network.network_address)
            else:
                lookup_ip = ip_or_cidr

            ip_whois = IPWhois(lookup_ip)
            whois_result = ip_whois.lookup_rdap()

            owner = whois_result['network']['name']
            range_start = whois_result['network']['start_address']
            range_end = whois_result['network']['end_address']
            asn = whois_result['asn']

            print(f"{ip_or_cidr:<18} {range_start} - {range_end:<35} {asn:<10} {owner}")
        except Exception as e:
            print(f"Error performing whois for IP/CIDR: {ip_or_cidr} - {e}")

if __name__ == "__main__":
    main()
