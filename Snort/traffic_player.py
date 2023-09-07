from scapy.all import *
from scapy.layers import http
from random import randrange
from random import randbytes
from ipaddress import IPv4Network, IPv4Address
from time import sleep
import string
import subprocess
from scapy.route import Route
#Doesn't quite need to be a class, but I don't feel comfortable not leaving as a function.
import re
import base64
IP_CIDR_RE = re.compile(r'(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}(?!\d|(?:\.\d))')
HEX_IDENTIFIER = re.compile(r'\|([0-9a-fA-F]{2} {0,1}){1,}\|')
BLACKLIST_IPS = []
BLACKLIST_PORTS = []
KNOWN_SERVICES= ['pop3','http']
CONTENT_MODIFIERS = ['depth:','offset:','distance:','within:','isdataat:','pcre:']
SUPPORTED_NEXT = ['base64_decode:','base64_data']
TEMP_BAD = ''
BAD_HEXSTRINGS = []
BLACKLIST_MACS = []
TLDs=None
UAs=None
#these are separate because the list is different, and corresponds to http
HTTP_OPTS = ['http_cookie','http_header','http_uri','http_raw_cookie','http_raw_header','http_raw_uri','http_stat_code','uricontent','urilen','http_method']
#yes, technically it should have /,= but these will make snort stop processing, and an '==' is added to the end.
#yes it should technically have '+' but this causes a payload length issue because it makes x64 decode to unicode and not ascii which makes detections a little inconsistent.
x64_RANDOM_CHAR_LIST='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+'
#PCRE IS BASIC NEEDS WORK
#NEED TO REFORMAT DATA FOR ISDATAAT
#BUG: Using '!' breaks future plays of same rule... lol.
with open('Snort/config/HTTP_Usr_Agts.txt','r') as f:
            UAs = f.readlines()
            f.close
with open('Snort/config/TLDs.txt','r') as f:
    TLDs = f.readlines()
    f.close

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
with open('Snort/config/blacklist_macs.txt', 'r') as f:
    BLACKLIST_MACS = f.readlines()
    f.close
for i,ele in enumerate(BLACKLIST_MACS):
    BLACKLIST_MACS[i] = ele.strip()

with open('Snort/config/Routes.txt','r') as f:
    myroutes=f.readlines()
    f.close
for x in myroutes:
    if not x.startswith('#'):
        ci = x.split(' ')[0].strip()
        g = x.split(' ')[1].strip()
        conf.route.add(net=ci,gw=g)

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
    
    def __init__(self, header, contents, client_mac, server_mac,sender_ip,recv_ip, MS = None):
        self.traffic_protocol = None
        self.client = sender_ip
        self.client_port = None
        self.server = recv_ip
        self.server_port = None
        self.payload_flow = None
        self.payload_service = None
        self.payload = None
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.base64_encode_next_payload=False
        self.base64_encode_offset = 0
        self.base64_encode_num_bytes = 0
        self.isdataat = 0
        self.sticky_x64_decode = False
        self.http_modifiers= {'http_cookie':'','http_header':bytearray(),'http_uri':bytearray('/'.encode('latin_1')),'http_raw_cookie':'',
        'http_raw_header':'','http_raw_uri':'','http_stat_code':'','uricontent':'/','urilen':'','http_method':'GET'}
        self.build_traffic(header,contents)
        if MS == 'S':
            while True:
                await_orders()
        
    def await_orders():
        if True:
            pass
        pass
    def get_random_mac(self):
        global BLACKLIST_MACS
        choices='1234567890ABCDEF'
        rval = 'FF:FF:FF:FF:FF:FF'
        while  rval in BLACKLIST_MACS :
            rval = ''
            for x in range(0,6):
                rval +=random.choice(choices)
                rval +=random.choice(choices)
                rval +=':'
            rval = rval[:-1]
        return rval


    #------------------------------------------------------------------#
    def build_traffic(self,header,contents):
        #rule header build  
        self.traffic_protocol = header['protocol']
        if self.client is None or self.client =='RANDOM':
            self.client = str(self.get_ip_address(header['rule_ip_src']))
        self.client_port = self.get_port(header['rule_src_p'])
        if self.server is None or self.server =='RANDOM':
            self.server = str(self.get_ip_address(header['rule_ip_dst']))
        self.server_port = self.get_port(header['rule_dst_p'])
        if self.client_mac is None or self.client_mac == 'RANDOM':
            self.client_mac = self.get_random_mac()
        if self.server_mac is None or self.server_mac == 'RANDOM':
            self.server_mac = self.get_random_mac()     
        #Rule contents build
        self.payload_flow = self.get_flow(contents)
        if self.payload_flow[0] =="from_server":
            placehold = self.client_port
            self.client_port = self.server_port
            self.server_port = placehold

        self.payload_service = self.get_service(contents)
        #REALLY don't need this.  Instead need to modify the get_payload & Payload_helper functions to add to our dictionary of HTTP opts.        
        self.payload = self.get_payload(contents)
        print(f"Service:{self.payload_service}")
        print(f"Protocol:{self.traffic_protocol}")
        print(f"{self.client_mac} AT {self.client}:{self.client_port} -> {self.server_mac} AT {self.server}:{self.server_port}")
        
        print(f"Flow:{self.payload_flow}")
        print("|--Payload--|")
        print(self.payload)
        if self.payload_service in 'http':
            print(self.http_modifiers)
        print('|-----------|\n')
        
    def send_full_convo(self, bcast = None):
        opts = [('SAckOK','')]
        #send(IP(src=self.client, dst=self.server, flags='DF')/TCP(sport=self.client_port,  flags='S',  dport=self.server_port,options=opts))
        if bcast is None:
            client_IP_Layer = Ether(src=self.client_mac,dst=self.server_mac)/IP(src=self.client, dst=self.server)
            server_IP_Layer = Ether(src=self.server_mac,dst=self.client_mac)/IP(src=self.server,dst=self.client)
        else:
            client_IP_Layer = IP(src=self.client, dst=self.server)
            server_IP_Layer = IP(src=self.server,dst=self.client)
        if self.payload_flow[1] == 'established':
            client_Hello = client_IP_Layer/TCP(sport=self.client_port, dport=self.server_port,  flags='S',  options=opts)
            if bcast is None:
                sendp(client_Hello, verbose=False)
            else:
                send(client_Hello, verbose=False)
            Server_SA = server_IP_Layer/TCP(sport=self.server_port,dport = self.client_port, flags='SA', seq=client_Hello.seq, ack=client_Hello.ack + 1,options = opts)
            if bcast is None:
                sendp(Server_SA, verbose=False)
            else:
                send(Server_SA, verbose=False)
            client_A = client_IP_Layer/TCP(sport=self.client_port, dport=self.server_port, flags ='A', seq=Server_SA.seq + 1, ack=Server_SA.ack)
            if bcast is None:
                sendp(client_A, verbose=False)
            else:
                send(client_A, verbose=False)
        serv_pload = None
        client_payload = None
        if self.payload_flow[0] == 'from_server':
            serv_pload = self.payload
            client_payload = bytearray(self.get_valid_random_bytes(randrange(1,len(self.payload))))
        else:
            serv_pload = bytearray(self.get_valid_random_bytes(randrange(1,len(self.payload))))
            client_payload = self.payload
        if self.payload_flow[1] == 'established':
            Server_payload = server_IP_Layer/TCP(sport = self.server_port, dport = self.client_port, flags='PA', seq = client_A.seq, ack = client_A.ack)/serv_pload
        else:
            Server_payload = server_IP_Layer/TCP(sport = self.server_port, dport = self.client_port, flags='PA',)/serv_pload
        if bcast is None:
            sendp(Server_payload, verbose=False)
        else:
            send(Server_payload, verbose=False)

        Client_Resp_1 = client_IP_Layer/TCP(sport = self.client_port, dport = self.server_port, flags='PA', seq = Server_payload.seq, ack = len(Server_payload[Raw].load))/client_payload
        if bcast is None:
            sendp(Client_Resp_1, verbose=False)
        else:
            send(Client_Resp_1, verbose=False)

        client_A = client_IP_Layer/TCP(sport = self.client_port, dport = self.server_port, flags='A',seq = Server_payload.seq, ack= len(Server_payload[Raw].load))
        if bcast is None:
            sendp(client_A, verbose=False)
        else:
            send(client_A, verbose=False)

        server_A = server_IP_Layer/TCP(sport = self.server_port, dport = self.client_port, flags='A', seq = Server_payload.seq, ack=len(Client_Resp_1[Raw].load))
        if bcast is None:
            sendp(server_A, verbose=False)
        else:
            send(server_A, verbose=False)

        server_pre_fin_psh = server_IP_Layer/TCP(sport = self.server_port,dport = self.client_port, flags='FPA', seq = len(Server_payload[Raw].load) + 1, ack = len(Client_Resp_1[Raw].load) )/bytearray(self.get_valid_random_bytes(randrange(1,len(Client_Resp_1[Raw].load)+2)))
        if bcast is None:
            sendp(server_pre_fin_psh, verbose=False)
        else:
            send(server_pre_fin_psh, verbose=False)

        client_FA = client_IP_Layer/TCP(sport=self.client_port, dport=self.server_port, flags='FA', seq=len(Client_Resp_1[Raw].load)+ 1, ack=len(server_pre_fin_psh[Raw].load))
        if bcast is None:
            sendp(client_FA, verbose=False)
        else:
            send(client_FA, verbose=False)

        serv_fin_ack = server_IP_Layer/TCP(sport=self.server_port, dport=self.client_port, flags='A', seq=client_FA.ack, ack=client_FA.seq +1)
        if bcast is None:
            sendp(serv_fin_ack, verbose=False)
        else:
            send(serv_fin_ack, verbose=False)
        #send(serv_signoff)
    def send_udp_convo(self, bcast=None):
        opts = [('SAckOK','')]
        #send(IP(src=self.client, dst=self.server, flags='DF')/TCP(sport=self.client_port,  flags='S',  dport=self.server_port,options=opts))
        if bcast is None:
            client_IP_Layer = Ether(src=self.client_mac,dst=self.server_mac)/IP(src=self.client, dst=self.server)
            server_IP_Layer = Ether(src=self.server_mac,dst=self.client_mac)/IP(src=self.server,dst=self.client)
        else:
            client_IP_Layer = IP(src=self.client, dst=self.server)
            server_IP_Layer = IP(src=self.server,dst=self.client)
        
        for i in range(10):
            sendp(client_IP_Layer/UDP(sport = self.client_port, dport=self.server_port)/self.payload)
            sendp(server_IP_Layer/UDP(sport = self.server_port, dport=self.client_port)/self.payload)
    def send_full_http(self, bcast = None):
        #self.http_modifiers= {'http_cookie':'','http_header':'','http_uri':'/','http_raw_cookie':'',
        #'http_raw_header':'','http_raw_uri':'','http_stat_code':'','uricontent':'/','urilen':'','http_method':'GGET'}
        global TLDs, UAs
        #REMOVE THIS POST TESTING
        

        letters = string.ascii_lowercase
        
        host = ''.join(random.choice(letters) for i in range(random.randint(5,20))) + '.'+random.choice(TLDs).strip().lower()
        
        Usr_Agent = ''.join(random.choice(UAs))
        Usr_Agent = Usr_Agent.strip().strip(' ')
        Get_Accept = '*/*'
        Get_encode = 'gzip, deflate'
        
        opts = [('SAckOK','')]
        if bcast is None:
            client_IP_Layer = Ether(src=self.client_mac,dst=self.server_mac)/IP(src=self.client, dst=self.server)
            server_IP_Layer = Ether(src=self.server_mac,dst=self.client_mac)/IP(src=self.server,dst=self.client)
        else:
            client_IP_Layer = IP(src=self.client, dst=self.server)
            server_IP_Layer = IP(src=self.server,dst=self.client)     
        theseq=0
        theack=0
        if self.payload_flow[1] == 'established':
            
            client_Hello = client_IP_Layer/TCP(sport=self.client_port, dport=self.server_port,  flags='S',  options=opts)
            sendp(client_Hello, verbose=False)

            Server_SA = server_IP_Layer/TCP(sport=self.server_port,dport = self.client_port, flags='SA', seq=client_Hello.seq, ack=client_Hello.ack + 1,options = opts)
            sendp(Server_SA, verbose=False)

            client_A = client_IP_Layer/TCP(sport=self.client_port, dport=self.server_port, flags ='A', seq=Server_SA.seq + 1, ack=Server_SA.ack)
            sendp(client_A, verbose=False)
            theseq=client_Hello.seq
            theack=client_Hello.ack + 1
        unknown_load=bytearray()
        if self.payload_flow[0] =='from_client':
            if len(self.http_modifiers['http_header']) >= 1:
                header_opts = self.http_modifiers['http_header'].decode('latin_1').split('\r\n')
                for x in header_opts:
                    if 'User-Agent:' in x:
                        if 'User-Agent: ' in x:
                            Usr_Agent = x[len('User-Agent: '):]
                        else:
                            Usr_Agent = x[len('User-Agent'):]
                    elif 'Host:' in x:
                        host=x
                    elif 'Accept:' in x:
                        Get_Accept = x
                    else:
                        if len(x.lower())>1:
                            tstr = x.lower()
                            for tl in TLDs:
                                y = '.' + tl.lower().strip()
                                if tstr.endswith(y):
                                    if x.startswith(': '):
                                        x = x[2:]
                                    elif x.startswith(':'):
                                        x = x[1:]
                                    host=x
                                    break
                if 'User-Agent:'.encode('latin_1') in self.payload and len(self.payload) > 1:
                    unknown_load = self.payload.decode('latin_1').split(':')
                    unknown_load = {unknown_load[0]:unknown_load[1]}
                    Usr_Agent=None


            Server_init_http = client_IP_Layer/TCP(sport=self.client_port,dport = self.server_port, flags='PA', seq=theseq, ack=theack,options = opts)/http.HTTP()/http.HTTPRequest(Unknown_Headers=unknown_load,Method=self.http_modifiers['http_method'],User_Agent=Usr_Agent,Host=host,Accept=Get_Accept,Path=self.http_modifiers['http_uri'])/self.payload    
            if bcast is None:
                sendp(Server_init_http, verbose=False)
            else:
                send(Server_init_http, verbose=False)
            #'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF="http://www.google.com/">here</A>.\n</BODY></HTML>'
            serv_payload = bytearray('<HTML><BODY>'.encode('latin_1')) + self.get_valid_random_bytes(randrange(200,600)) + bytearray('</BODY></HTML>'.encode('latin_1'))
        else:
            serv_payload=self.payload

        Server_resp_init = server_IP_Layer/TCP(sport=self.server_port,dport=self.client_port, flags='A', seq=Server_init_http.seq, ack= Server_init_http.ack)
        if bcast is None:
            sendp(Server_resp_init,verbose=False)
        else:
            send(Server_resp_init,verbose=False)
        Server_Send_HTML=server_IP_Layer/TCP(sport=self.server_port,dport=self.client_port,flags='PA', seq=Server_init_http.seq,ack=Server_resp_init.ack)/http.HTTP()/http.HTTPResponse(Server=random.choice(['Apache','gws']), Location=bytearray('http://'.encode('latin_1'))+bytearray(host.encode('latin_1'))+self.http_modifiers.get('http_uri'),Content_Type='text/html; charset=UTF-8')/serv_payload
        if bcast is None:
            sendp(Server_Send_HTML,verbose=False)
        else:
            send(Server_Send_HTML,verbose=False)
        #client_FA = client_IP_Layer/TCP(sport=self.client_port,dport=self.server_port,flags='FA', seq=)

    def send_traffic(self, bcast=None):
        if self.traffic_protocol == 'tcp':
            if self.payload_service in 'http':
                self.send_full_http(bcast)
                
            else:
                self.send_full_convo(bcast)
        elif self.traffic_protocol =='udp':
            self.send_udp_convo(bcast)
        
#Potential for infinite loops below function.  Future: Get rid of by checking the src. IP ranges and only finding IP addresses for randomization outside.
#Also Need to include RFC 1918 addresses for random IP addresses for local IPs for hosts.
    def get_ip_address(self,hostname):
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
                if self.check_blacklist_ip(my_ip):
                    my_ip = None
        elif IP_CIDR_RE.match(hostname):
            ip_block = IPv4Network(hostname)
            my_ip = str(ip_block[randrange(0,ip_block.num_addresses- 3)])
            
            if self.check_blacklist_ip(hostname):
                print(f'Blacklisted IPv4 network found: {hostname}')
                my_ip = None    
        else:
            try:
                IPv4Address(hostname)
                my_ip = hostname
                if self.check_blacklist_ip(my_ip):
                    print(f'Blacklisted IPv4 address specified: {my_ip}')
                    my_ip = None

            except ValueError:
                print(f'Invalid IPv4 address specified: {hostname}')
        if len(TEMP_BAD) > 0:
            BLACKLIST_IPS.remove(TEMP_BAD)
            TEMP_BAD = None
        return my_ip

    def check_blacklist_ip(self,my_ip):
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

    def get_port(self,port):
        my_port = 0
        if str(port).startswith('!'):
            port = port[1:]
            if port.startswith('['):
                port=port[1:-1]
            if ':' in port:
                port = port.split(':')
                my_port = random.choice([randrange(1,int(port[0])-1),randrange(int(port[1])+1,65535)])
                return my_port
            else:
                my_port = randrange(1,65535)
        if type(port) is list:
            for cnt,port_obj in enumerate(port):
                port[cnt] = self.get_port(port_obj)
            return random.choice(port)    
        if port is None or str(port) == 'any':
            my_port = randrange(1,65535)
            while my_port in BLACKLIST_PORTS:
                my_port = randrange(1,65535)
        #SEEE https://www.sbarjatiya.com/notes_wiki/index.php/Configuring_snort_rules#Specifying_source_and_destination_ports
        elif '[' in str(port):
            port_def = port.strip('[').strip(']')
            port_def = port_def.split(',')
            start_p = self.get_port(port_def[0])
            end_p = start_p
            if len(port_def) > 1:
                end_p = self.get_port(port_def[1])
            port_rng = [start_p, end_p]
            my_port = random.choice(port_rng)
            return int(my_port)
                
        elif str(port).startswith(':'):
            my_port = randrange(1,int(port[1:]))
            
            while my_port in BLACKLIST_PORTS:
                my_port = randrange(1,int(port[1:]))
        elif str(port).endswith(':'):
            port = port.strip(':')
            #TEMP NEEDS TO BE REWORKED.
            try:
                my_port =  randrange(int(port),65535)
            except:
                my_port = 1024
            while my_port in BLACKLIST_PORTS:
                my_port = randrange(int(port[:-1]),65535)
        elif ':' in str(port):
            nums = ''
            #TEMP.  NEEDS TO BE REWORKED.
            if ',' in port:
                nums = port.strip('[').strip(']').strip(':')
                nums = nums.split(',')
            else:
                nums = str(port).strip('[').strip(']').split(':') 
            my_port =  randrange(int(nums[0]),int(nums[1]))
            while my_port in BLACKLIST_PORTS:
                my_port = randrange(int(nums[0]),int(nums[1]))
        else:
            return int(port)
        return my_port

    def get_flow(self,cont):
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

    def set_next_content_opts(self,itemno):
        if 'base64_decode:'in itemno[0]:
            self.base64_encode_next_payload = True
            the_x64data = itemno[1].split(',')
            for variablex64 in the_x64data:
                if 'offset' in variablex64:
                    self.base64_encode_offset = int(str(variablex64).replace('offset','').replace(' ',''))
                if 'bytes' in variablex64:
                    self.base64_encode_num_bytes = int(str(variablex64).replace('bytes','').replace(' ',''))
        if 'base64_data' == itemno[0]:       
            self.sticky_x64_decode = True
    def get_service(self,cont):
        global HTTP_OPTS
        svc = 'general'
        for x in cont:
            if x[0] == 'metadata:service' or 'service' in x[0] or 'metadata:' in x[0]:
                if 'metadata' in x[0]:
                    meta = x[1].split(',')
                    for y in meta:
                        if 'service' in y:
                            k = y.split(' ')
                            if k[0] =='':
                                svc=k[2]
                            else:
                                svc = k[1]
                            break               
            for op in HTTP_OPTS:
                if op is not None and x[0].lower() in op:
                    svc = 'http'
            if svc in 'http':
                break
            else:
                svc = x[1]
            

        if svc in KNOWN_SERVICES  :
            return svc
        else:
            return "general"#KNOWN_SERVICES

    def get_payload(self,cont):
        payload = bytearray()
        #Find where we have content, if we do....
        x64_additions = []
        http_opt = None
        for count,details in enumerate(cont):
            if details[0] in SUPPORTED_NEXT:
                self.set_next_content_opts(details)
            elif details[0] == 'content:' or details[0] == 'pcre:':
                    #need helper option here, to append to string, we don't need a flag, We need to skip ahead in the enumeration until we reach what it is we seek. This needs to be done in an array.                    
                if not self.base64_encode_next_payload and not self.sticky_x64_decode:
                    curr_cap,count,http_opt=self.payload_helper(cont,count)
                    if http_opt is None and curr_cap is not None:
                        payload.extend(curr_cap)
                    elif curr_cap is not None:
                        if 'header' in http_opt:
                            self.http_modifiers['http_header'] += bytearray(curr_cap+bytearray('\r\n'.encode('latin_1')))
                        elif 'uri' in http_opt:
                            if len(self.http_modifiers['http_uri']) > 1:
                                self.http_modifiers['http_uri'] +=bytearray(curr_cap)
                            else:
                                self.http_modifiers.update({'http_uri':bytearray(curr_cap)})
                        else:
                            self.http_modifiers.update({http_opt:bytearray(curr_cap)})
                    details = cont[count]
                else:
                    curr_cap,count,http_opt=self.payload_helper(cont,count)
                    curr_cap = base64.b64decode(curr_cap)
                    #I know this is really weird, but I did something I can't remember, and now this is the how we get x64 of the correct length. I know, super dumb, but it works? somehow?
                    #I'll fix it later, but this really is something I don't want to chase at the moment. It wasn't fun to figure out, granted I was playing overwatch & drinkin w/ some friends while coding it.
                    #After-all this is just a fun project that I have been doing.
                    if curr_cap is not None:
                        curr_cap = curr_cap.decode('utf-8')
                    if http_opt is not None:
                        self.http_modifiers.update({http_opt:curr_cap})
                    else:
                        x64_additions.append(curr_cap)

        #I know I can do this in a better/faster way, but at the time this helped me troubleshoot.
        true_addition = bytearray()
        for x in x64_additions:
            addme = x
            if addme.endswith('=='):
                addme = addme[:-2]
            true_addition +=str(addme).encode('utf-8')

        true_addition= base64.b64encode(true_addition)

        payload += true_addition[:-1] + self.get_valid_random_bytes(self.isdataat)
        return payload

    def get_valid_random_bytes(self,size):
        global x64_RANDOM_CHAR_LIST
        if self.sticky_x64_decode or self.base64_encode_next_payload:
            r_string = ''.join(random.choice(string.ascii_letters+string.digits)for i in range(size))
            r_string = r_string
            
            return base64.b64encode(r_string.encode('utf-8'))
        else:
            return randbytes(size)     
#currently doesn't support negative numbers in dist/offset
    def payload_helper(self,cont,count):
        not_flag = False
        if 'pcre' in cont[count][0] :
            return self.reverse_pcre(cont[count][1]),count+1,None    
        if cont[count][1].startswith('!'):
            cont[count][1] = cont[count][1][1:]
            not_flag=True
        if str(cont[count][1]).startswith('\"') :
            cont[count][1] = cont[count][1][1:-1]
        build = bytearray()
        curr_loc = count 
        dofill=False
        if self.isdataat !=0:
            dofill=True
        orig = bytearray(self.get_content(cont[count][1]))    
        build.extend(orig)
        if not_flag:
            build = bytearray(self.get_valid_random_bytes(len(build)))
            
        curr_loc +=1
        paysize = 0
        offset = 0
        within = 0
        isdat =0
        depth=0
        #Need to check for banned hex strings.
        http_option = None
        if self.base64_encode_next_payload or self.sticky_x64_decode:

            if self.base64_encode_num_bytes == 0:
                self.base64_encode_num_bytes = len(build)
            build = bytearray(build[:self.base64_encode_offset] + base64.b64encode(build[self.base64_encode_offset:self.base64_encode_offset+self.base64_encode_num_bytes]) + build[self.base64_encode_offset+self.base64_encode_num_bytes:])
            #if str(build.decode('utf-8')).endswith('=='):
            #    build = build[:-2]
            self.base64_encode_num_bytes = 0
            self.base64_encode_offset=0
            self.base64_encode_next_payload=False


        while curr_loc < len(cont) and (cont[curr_loc][0] in CONTENT_MODIFIERS or cont[curr_loc][0] in HTTP_OPTS) :
            if 'depth:' == cont[curr_loc][0]:
                depth += int(cont[curr_loc][1])
            elif 'within:' in cont[curr_loc][0]:
                within=  int(cont[curr_loc][1])

            elif 'pcre:' in cont[curr_loc][0]:
                if build is not None and build.decode('latin_1') in self.reverse_pcre(cont[curr_loc][1]).decode('latin_1'):
                    build = self.reverse_pcre(cont[curr_loc][1])
                else:
                    break

                
            elif 'isdataat:' == cont[curr_loc][0]:
                if dofill== False:
                    self.isdataat = cont[curr_loc][1].split(',')
                    if self.isdataat[0].startswith('!'):
                        self.isdataat = 0
                    else:
                        self.isdataat = int(self.isdataat[0]) + 30
                else:
                    isdat = cont[curr_loc][1].split(',')
                    isdat = int(isdat[0])

            elif 'offset:' == cont[curr_loc][0] or 'distance:' == cont[curr_loc][0]:
                offset += int(cont[curr_loc][1])
            #THIS IS A BAD WAY OF DOING THIS

            else:
                for cnt,http_opt in enumerate(HTTP_OPTS):
                    if http_opt == cont[curr_loc][0]:
                        http_option = cont[curr_loc][0]
                break
            curr_loc +=1

        if offset > 0:
            build = bytearray(self.get_valid_random_bytes(offset)) + build
        if paysize > 0 :
            build.extend(self.get_valid_random_bytes(paysize))
        if self.isdataat> 0 and dofill:
            build.extend(bytearray(self.get_valid_random_bytes(self.isdataat)))                
            #self.isdataat = isdat
        if depth > 0:
            build.append(self.get_valid_random_bytes(depth))    
        if not_flag:
            exclude_me = bytearray(self.get_content(cont[count][1]))
            while exclude_me in build:

                build = build.replace(exclude_me,self.get_valid_random_bytes(len(exclude_me)))

        return build,curr_loc,http_option

    def get_content(self,le_string):

        content = le_string
        payload_content = bytearray()
        if content.startswith('\"') and content.endswith('\"'):
            content = content[1:-1]
        content = re.sub(HEX_IDENTIFIER,self.hex_match,content)
        payload_content.extend(content.encode('latin_1'))
        return payload_content

    def reverse_pcre(self,the_regex):

        if the_regex.startswith('\"') and the_regex.endswith('\"'):
            the_regex = the_regex[1:-1]
        if the_regex.startswith('/^'):
            the_regex = the_regex[2:]
        re_opts = the_regex[the_regex.rfind('/')+1:]
        the_regex = the_regex[:the_regex.rfind('/')]
        #TODO IMPLEMENT SNORT OPTIONS.

        the_regex = self.rstring_arrbuilder(the_regex)
        with open('./Snort/pcre_gen.txt','w') as f:
            f.write(the_regex)
            f.close()
        result=subprocess.run([f'perl','.\\Snort\\reverse_pcre.pl', the_regex], shell=True, stdout=subprocess.PIPE)
        with open('./Snort/pcre_gen.txt','r') as f:
            the_regex = f.read()
            f.close()
        if 'D' in re_opts:
            if 'Cookie' in the_regex:
                self.http_modifiers.update({'http_cookie':bytearray(the_regex.encode('latin_1'))})
                return None
        if 'U' in re_opts:
            self.http_modifiers.update({'http_uri':bytearray(the_regex.encode('latin_1'))})
            return None

        return bytearray(the_regex.encode('latin_1'))
    def rstring_arrbuilder(self, the_regex):
        if '\s' in the_regex:
            the_regex = the_regex.replace('\\s',' ')
        if '\:' in the_regex:
            the_regex = the_regex.replace('\\:','\\\\:')
        matching_unsupported_negate = re.findall('\[\^.+\]',the_regex)

        my_re = the_regex

        for x,negated in enumerate(matching_unsupported_negate):
            supported_characters = string.ascii_letters + string.digits
            replacement_string = negated[2:-1]
            if '\s' in negated:
                supported_characters = supported_characters.replace('\t','').replace('\n','').replace('\r','').replace('\x0b','').replace('\x0c','')
            if '\\n' in negated:
                supported_characters = supported_characters.replace('\\n','')
            for i in replacement_string:
                if i in supported_characters:
                    supported_characters = supported_characters.replace(i,'')
            my_re = my_re.replace(matching_unsupported_negate[x],'['+supported_characters.replace('[','\[').replace(']','\]').replace('+','\+').replace('-','\+').replace('>','').replace('<','').replace('\'','').replace('{','').replace('^','') +']') 

        return my_re

    def hex_match(self,the_match):
        match1 = the_match.group().strip('|')
        content = bytearray.fromhex(match1).decode('latin_1')
        
        return content

if __name__ == '__main__':
    header = {'rule_action': 'alert', 'protocol': 'tcp', 'rule_ip_src': 'any', 'rule_src_p': '110', 'rule_direction': '->', 'rule_ip_dst': 'any', 'rule_dst_p': 'any'}
    content = [['msg:', '"PROTOCOL-POP APOP USER overflow attempt"'], ['flow:', 'to_server,established'], ['content:', '"APOP"'], ['isdataat:', '256,relative'], ['pcre:', '"/^APOP\s+USER\s[^\\n]{256}/smi"'], ['metadata:', 'ruleset community, service pop3'], ['reference:', 'bugtraq,9794'], ['reference:', 'cve,2004-2375'], ['classtype:', 'attempted-admin'], ['sid:', '2409'], ['rev:', '11']]    
    ok = traffic_player(header,content,None, None)
    #ok.build_traffic(header,content)
    #while True:
    for x in range(1):
        ok.send_traffic()
        sleep(5)
    #build_traffic(header, content)
