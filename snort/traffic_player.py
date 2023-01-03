from scapy.all import *
from pprint import pprint
from random import randrange
from ipaddress import IPv4Network, IPv4Address

import re
IP_CIDR_RE = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}(?!\d|(?:\.\d))")
BLACKLIST_IPS = []
TEMP_BAD = None

with open('Snort/config/blacklist_ips.txt', 'r') as f:
    BLACKLIST_IPS = f.readlines()
    f.close

for i,ele in enumerate(BLACKLIST_IPS):
    BLACKLIST_IPS[i] = ele.strip()

#------------------------------------------------------------------#
def build_traffic(header,contents):
    traffic_protocol = header['protocol']
    client = get_ip_address(header['rule_ip_src'])
    client_port = get_port(header['rule_src_p'])
    print(client)

def get_ip_address(hostname):

    my_ip = None
    if str(hostname).startswith('!'):
        TEMP_BAD = hostname[1:]
        if TEMP_BAD not in BLACKLIST_IPS:
            BLACKLIST_IPS.append(TEMP_BAD)
        else:
            TEMP_BAD = None
        hostname = 'any'

    if hostname == 'any':
        while my_ip is None:
            my_ip = f'{randrange(1,255)}.{randrange(1,255)}.{randrange(1,255)}.{randrange(1,255)}'
            if check_blacklist_ip(my_ip):
                my_ip = None
    elif IP_CIDR_RE.match(hostname):
        ip_block = IPv4Network(hostname)
        my_ip = str(ip_block[randrange(0,ip_block.num_addresses- 3)])
        
        if check_blacklist_ip(hostname):
            print(f'Blacklisted IPv4 network found: {hostname}')
            my_ip = None    
    else:
        try:
            IPv4Address(hostname)
            my_ip = hostname
            if check_blacklist_ip(my_ip):
                print(f'Blacklisted IPv4 address specified: {my_ip}')
                my_ip = None

        except ValueError:
            print(f'Invalid IPv4 address specified: {hostname}')
    if TEMP_BAD is not None:
        BLACKLIST_IPS.remove(TEMP_BAD)
        TEMP_BAD = None
    return my_ip

def check_blacklist_ip(my_ip):
    bad = False
    if IP_CIDR_RE.match(my_ip):
        
        ipv4_network_spec = IPv4Network(my_ip)
        for bad_ip in BLACKLIST_IPS:
            bad_network = IPv4Network(bad_ip)
            if ipv4_network_spec.subnet_of(bad_network) or bad_network.subnet_of(ipv4_network_spec):
                bad = True
    else:            
        for bad_ip in BLACKLIST_IPS:
            ipv4_network_spec = IPv4Network(bad_ip)
            if IP_CIDR_RE.match(bad_ip):
                if IPv4Address(my_ip) in ipv4_network_spec:
                    bad=True
                    break
            else:
                if my_ip == bad_ip:
                    bad=True
    return bad

def get_port(port):
    
    exit(0)

header = {'rule_action': 'alert', 'protocol': 'tcp', 'rule_ip_src': 'any', 'rule_src_p': '110', 'rule_direction': '->', 'rule_ip_dst': 'any', 'rule_dst_p': 'any'}
build_traffic(header, None)


