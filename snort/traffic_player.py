from scapy.all import *
from pprint import pprint
from random import randrange
from ipaddress import IPv4Network, IPv4Address
#Doesn't quite need to be a class, but I don't feel comfortable not leaving as a function.
import re
IP_CIDR_RE = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}(?!\d|(?:\.\d))")
BLACKLIST_IPS = []
KNOWN_SERVICES= ['pop3']
TEMP_BAD = None

with open('Snort/config/blacklist_ips.txt', 'r') as f:
    BLACKLIST_IPS = f.readlines()
    f.close

for i,ele in enumerate(BLACKLIST_IPS):
    BLACKLIST_IPS[i] = ele.strip()

#------------------------------------------------------------------#
def build_traffic(header,contents):
    #rule header build
    traffic_protocol = header['protocol']
    client = get_ip_address(header['rule_ip_src'])
    client_port = get_port(header['rule_src_p'])
    server = get_ip_address(header['rule_ip_dst'])
    server_port = get_port(header['rule_dst_p'])
    #Rule contents build
    payload_form = get_flow(header['flow'])
    
    payload_service = get_service(contents['metadata:service'])


    print(client)
#Potential for infinite loops below function.  Future: Get rid of by checking the src. IP ranges and only finding IP addresses for randomization outside.
#Also Need to include RFC 1918 addresses for random IP addresses for local IPs for hosts.
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
    if str(port) == 'any':
        return randrange(1,65535)
    elif str(port).startswith(':'):
        return randrange(1,int(port[1:]))
    elif str(port).endswith(':'):
        return randrange(int(port[1:]),65535)
    elif ':' in str(port):
        nums = str(port).split(':')    
        return randrange(int(nums[0]),int(nums[1]))
    else:
        return randrange(port)

def get_flow(flow):
    payload_direction='from_client'
    payload_form = None
    if ',' in flow:
        parameters = flow.split(',')
        if parameters[0] in 'to_client' or parameters[0] in 'from_server':
            payload_direction = 'from_server'
        payload_form = payload_form
    else:
        if flow in 'to_client' or flow in 'from_server':
            payload_direction = 'from_server'
    return [payload_direction,payload_form]

def get_service(svc):
    for svc
    if svc not in KNOWN_SERVICES :
        return None
    else:
        return svc

header = {'rule_action': 'alert', 'protocol': 'tcp', 'rule_ip_src': 'any', 'rule_src_p': '110', 'rule_direction': '->', 'rule_ip_dst': 'any', 'rule_dst_p': 'any'}
build_traffic(header, None)


