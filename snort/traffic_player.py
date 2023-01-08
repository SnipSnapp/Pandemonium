from scapy.all import *
from pprint import pprint
from random import randrange
from random import randbytes
from ipaddress import IPv4Network, IPv4Address
#Doesn't quite need to be a class, but I don't feel comfortable not leaving as a function.
import re
IP_CIDR_RE = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}(?!\d|(?:\.\d))")
BLACKLIST_IPS = []
BLACKLIST_PORTS = []
KNOWN_SERVICES= ['pop3']
CONTENT_MODIFIERS = ['depth:','offset:','distance:','within:','http_header:','isdataat:']
TEMP_BAD = ''
BAD_HEXSTRINGS = []

with open('Snort/config/blacklist_ips.txt', 'r') as f:
        BLACKLIST_IPS = f.readlines()
        f.close

for i,ele in enumerate(BLACKLIST_IPS):
    BLACKLIST_IPS[i] = ele.strip()

with open('Snort/config/blacklist_ports.txt','r') as f:
    BLACKLIST_PORTS = f.readlines()
    f.close
for i,ele in enumerate(BLACKLIST_PORTS):
    BLACKLIST_PORTS[i] = int(ele.strip())

class traffic_player:


    with open('Snort/config/blacklist_ips.txt', 'r') as f:
        BLACKLIST_IPS = f.readlines()
        f.close

    for i,ele in enumerate(BLACKLIST_IPS):
        BLACKLIST_IPS[i] = ele.strip()

    with open('Snort/config/blacklist_ports.txt','r') as f:
        BLACKLIST_PORTS = f.readlines()
        f.close
    for i,ele in enumerate(BLACKLIST_PORTS):
        BLACKLIST_PORTS[i] = int(ele.strip())
    
    def __init__(self, header, contents, random_mac):
        self.traffic_protocol = None
        self.client = None
        self.client_port = None
        self.server = None
        self.server_port = None
        self.payload_flow = None
        self.payload_service = None
        self.payload = None
        self.build_traffic(header,contents,random_mac)

    #------------------------------------------------------------------#
    def build_traffic(self,header,contents, randomize_Mac):
        #rule header build    
        self.traffic_protocol = header['protocol']
        print(f"Protocol:{self.traffic_protocol}")
        self.client = str(get_ip_address(header['rule_ip_src']))
        self.client_port = get_port(header['rule_src_p'])
        self.server = str(get_ip_address(header['rule_ip_dst']))
        self.server_port = get_port(header['rule_dst_p'])
        
        print(f"{self.client}:{self.client_port} -> {self.server}:{self.server_port}")
        #Rule contents build
        self.payload_flow = get_flow(contents)
        print(f"Flow:{self.payload_flow}")
        if self.payload_flow[0] =="from_server":
            placehold = self.client_port
            self.client_port = self.server_port
            self.server_port = placehold

        self.payload_service = get_service(contents)
        print(f"Service:{self.payload_service}")
        
        self.payload = get_payload(contents)
        print("--Payload--")
        #print(payload.decode(encoding='latin_1'))
        print(self.payload)
        print(len(self.payload))
        print(int(math.log2(len(self.payload)*8)) + 1)

    def send_full_convo(self):
        print("Sending")
        opts = [('SAckOK','')]
        #send(IP(src=self.client, dst=self.server, flags='DF')/TCP(sport=self.client_port,  flags='S',  dport=self.server_port,options=opts))
        #print("sent 1 I guess")
        client_IP_Layer = IP(src=self.client, dst=self.server)
        server_IP_Layer = IP(src=self.server,dst=self.client)

        client_Hello = client_IP_Layer/TCP(sport=self.client_port, dport=self.server_port,  flags='S',  options=opts)
        send(client_Hello)

        Server_SA = server_IP_Layer/TCP(sport=self.server_port,dport = self.client_port, flags='SA', seq=client_Hello.seq, ack=client_Hello.ack + 1,options = opts)
        send(Server_SA)

        client_A = client_IP_Layer/TCP(sport=self.client_port, dport=self.server_port, flags ='A', seq=Server_SA.seq + 1, ack=Server_SA.ack)
        send(client_A)
        serv_pload = None
        client_payload = None
        if self.payload_flow[0] == 'from_server':
            serv_pload = self.payload
            client_payload = bytearray(randbytes(randrange(1,len(self.payload))))
        else:
            serv_pload = bytearray(randbytes(randrange(1,len(self.payload))))
            client_payload = self.payload
        
        Server_payload = server_IP_Layer/TCP(sport = self.server_port, dport = self.client_port, flags='PA', seq = client_A.seq, ack = client_A.ack)/serv_pload
        send(Server_payload)
        
        Client_Resp_1 = client_IP_Layer/TCP(sport = self.client_port, dport = self.server_port, flags='PA', seq = Server_payload.seq, ack = len(Server_payload[Raw].load))/client_payload
        send(Client_Resp_1)


        client_A = client_IP_Layer/TCP(sport = self.client_port, dport = self.server_port, flags='A',seq = Server_payload.seq, ack= len(Server_payload[Raw].load))
        send(client_A)

        server_A = server_IP_Layer/TCP(sport = self.server_port, dport = self.client_port, flags='A', seq = Server_payload.seq, ack=len(Client_Resp_1[Raw].load))
        send(server_A)

        server_pre_fin_psh = server_IP_Layer/TCP(sport = self.server_port,dport = self.client_port, flags='FPA', seq = len(Server_payload[Raw].load) + 1, ack = len(Client_Resp_1[Raw].load) )/bytearray(randbytes(randrange(1,len(Client_Resp_1[Raw].load))))
        send(server_pre_fin_psh)

        client_FA = client_IP_Layer/TCP(sport=self.client_port, dport=self.server_port, flags='FA', seq=len(Client_Resp_1[Raw].load)+ 1, ack=len(server_pre_fin_psh[Raw].load))
        send(client_FA)

        serv_fin_ack = server_IP_Layer/TCP(sport=self.server_port, dport=self.client_port, flags='A', seq=client_FA.ack, ack=client_FA.seq +1)
        send(serv_fin_ack)
        #send(serv_signoff)





        exit(0)    
    def send_traffic(self):
        print(self.payload_flow[1])
        if self.payload_flow[1] == 'established':
            self.send_full_convo()
            exit(0)
    

def random_mac():
    return 

#Potential for infinite loops below function.  Future: Get rid of by checking the src. IP ranges and only finding IP addresses for randomization outside.
#Also Need to include RFC 1918 addresses for random IP addresses for local IPs for hosts.
def get_ip_address(hostname):
    global TEMP_BAD
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
    if len(TEMP_BAD) > 0:
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
    my_port = 0
    if str(port) == 'any':
        my_port = randrange(1,65535)
        while my_port in BLACKLIST_PORTS:
            my_port = randrange(1,65535)
    elif str(port).startswith(':'):
        my_port = randrange(1,int(port[1:]))
        while my_port in BLACKLIST_PORTS:
            my_port = randrange(1,int(port[1:]))
    elif str(port).endswith(':'):
        my_port =  randrange(int(port[1:]),65535)
        while my_port in BLACKLIST_PORTS:
            my_port = randrange(int(port[1:]),65535)
    elif ':' in str(port):
        nums = str(port).split(':')    
        my_port =  randrange(int(nums[0]),int(nums[1]))
        while my_port in BLACKLIST_PORTS:
            my_port = randrange(int(nums[0]),int(nums[1]))
    else:
        return int(port)
    return my_port

def get_flow(cont):
    flow = ''
    for x in cont:
        if x[0] == 'flow:':
            flow=x[1]
    payload_direction='from_client'
    payload_form = None
    if ',' in flow:
        parameters = flow.split(',')
        if parameters[0] in 'to_client' or parameters[0] in 'from_server':
            payload_direction = 'from_server'
        payload_form = parameters[1]
    else:
        if flow in 'to_client' or flow in 'from_server':
            payload_direction = 'from_server'
    return [payload_direction,payload_form]

def get_service(cont):
    svc = None
    for x in cont:
        
        if x[0] == 'metadata:service':
            svc = x[1]
    if svc in KNOWN_SERVICES :
        return svc
    else:
        return KNOWN_SERVICES
#This gunna be one mamma-jamma of a function.
def get_payload(cont):
    payload = bytearray()
    #Find where we have content, if we do....
    for count,details in enumerate(cont):
        if details[0] == 'content:':
                #need helper option here, to append to string, we don't need a flag, We need to skip ahead in the enumeration until we reach what it is we seek. This needs to be done in an array.    
            curr_cap,count=payload_helper(cont,count)
            payload.extend(curr_cap)
            details = cont[count]
    return payload
            
            
#currently doesn't support negative numbers in dist/offset
def payload_helper(cont,count):
    not_flag = False

    if cont[count][1].startswith('!'):
        not_flag = True
    if str(cont[count][1]).startswith('\"') :
        cont[count][1] = cont[count][1][1:-1]
    build = bytearray()
    curr_loc = count 

    build.extend(get_content(cont[count][1]))
    curr_loc +=1
    paysize = 0
    offset = 0
    within = 0
    isdat =0
    #Need to check for banned hex strings.
    while cont[curr_loc][0] in CONTENT_MODIFIERS and curr_loc < len(cont):
        
        if 'depth:' == cont[curr_loc][0] or 'within:' == cont[curr_loc][0]:
            paysize += int(cont[curr_loc][1])
        if 'isdataat:' == cont[curr_loc][0]:
            isdat = cont[curr_loc][1].split(',')

            isdat = int(isdat[0])

        if 'offset:' == cont[curr_loc][0] or 'distance:' == cont[curr_loc][0]:
            offset += int(cont[curr_loc][1])
        curr_loc +=1
    if isdat > 0:
        build.extend(randbytes(isdat))
    if offset > 0:
        build = bytearray(randbytes(offset)) + build
    if paysize > 0:
        build.extend(randbytes(randrange(0,paysize)))
    if not_flag:
        build = bytearray(randbytes(len(build)))
    return build,curr_loc

def get_content(le_string):
    content = le_string
    payload_content = bytearray()
    if content.startswith('\"') and content.endswith('\"'):
        content = content[1:-1]

    if content.startswith('|') and content.endswith('|'):
        content = content[1:-1]
        content = content.split('|')
        for itemz in content_vars:
            if (' ' in itemz or len(itemz) > 1):
                payload_content.extend( bytearray.fromhex(itemz))
            if len(itemz) > 0 :
                payload_content.extend(itemz.encode('utf-8'))
    else:
        payload_content.extend(content.encode('utf-8'))
    return payload_content


header = {'rule_action': 'alert', 'protocol': 'tcp', 'rule_ip_src': 'any', 'rule_src_p': '110', 'rule_direction': '->', 'rule_ip_dst': 'any', 'rule_dst_p': 'any'}
content = [['msg:', '"PROTOCOL-POP libcurl MD5 digest buffer overflow attempt"'], ['flow:', 'to_client,established'],
 ['content:', '"+OK"'], ['content:', '"SASL"'], ['distance:', '0'], ['content:', '"DIGEST-MD5"'], ['distance:', '0'],
  ['content:', '"+"'], ['distance:', '0'], ['base64_decode:', 'relative'], ['base64_data', ''], ['content:', '"realm=|22|"'],
   ['isdataat:', '124,relative'], ['content:', '!"|22|"'], ['within:', '124'], ['metadata:service', 'pop3'],
    ['reference:', 'bugtraq,57842'], ['reference:', 'cve,2013-0249'], ['classtype:', 'attempted-user'],
     ['sid:', '26391'], ['rev:', '1']]

ok = traffic_player(header,content,False)
ok.build_traffic(header,content,False)
print("Build complete.")
ok.send_traffic()
#build_traffic(header, content)


