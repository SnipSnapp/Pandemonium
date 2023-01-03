from scapy.all import *
from pprint import pprint
serv = "192.168.68.55"
client = "192.168.68.56"
client_port = random.randint(1024,65535)
server_port = 110

def build_pcap(rule_parameters):
    


l4 = IP(src = client, dst = serv)

opts = [('MSS',1460), ('WScale', 2), ('WS', 128),('SAckOK','')]
pop3_init  = IP(src=client, dst=serv, flags='DF')/TCP(sport=client_port,  flags='S',  dport=server_port,options=opts)
send(pop3_init)
pprint(pop3_init)
pprint(pop3_init.seq)
pprint(pop3_init.ack)

pop3_snack  = IP(src=serv, dst = client)/TCP(sport=server_port,  flags='SA', dport=client_port, seq = pop3_init.seq, ack = pop3_init.ack + 1, options=opts)
send(pop3_snack)
pprint(pop3_snack)
pprint(pop3_snack.seq)
pprint(pop3_snack.ack)

pop3_ack = IP ( src=client, dst=serv) /TCP(sport=client_port,  flags='A', dport=server_port, seq=pop3_snack.ack, ack = pop3_snack.seq + 1, options=[('NOP',0),('NOP',0)])
send(pop3_ack)
pprint(pop3_ack)
pprint(pop3_ack.seq)
pprint(pop3_ack.ack)

send_hello = IP(src  = serv, dst = client)/TCP(sport = server_port, flags = 'PA',dport = client_port,seq=pop3_snack.seq + 1, ack = pop3_ack.ack)/"+OK POP server ready. H mimap40MHoUr-1VDxRD3Ui5-003eq2\r\n"
send(send_hello)

dns_query = IP(src=client, dst=serv)/TCP(sport=client_port,  flags='PA', dport=server_port, seq=pop3_snack.ack, ack = len(send_hello[Raw].load), options=[('NOP',0),('NOP',0)])/"+OKSASLDIGEST-MD5+\r\n"
send(dns_query)

hello_ack = IP(src = client,dst = serv)/TCP(sport=client_port,  flags='A', dport=server_port, seq=pop3_snack.ack, ack = len(send_hello[Raw].load))
send(hello_ack)

pprint(dns_query)
print(dns_query.seq)
print(dns_query.ack)
pprint(len(dns_query[Raw].load))

pop3_ack2 = IP( src=serv, dst=client)/TCP(sport=server_port,  flags='A', dport=client_port, seq=pop3_snack.ack, ack = len(dns_query[Raw].load))
send(pop3_ack2)
sign_off = IP(src = client, dst = serv)/TCP(sport = client_port, flags = 'FPA', dport=server_port, seq =pop3_snack.ack, ack =  )
finack = IP(src = serv, dst = client)/TCP(sport = server_port, flags='FA', dport = client_port, seq=pop3_snack.ack, ack = len(dns_query[Raw].load) + 1 )
send(finack)
ackack = IP(src = client, dst = serv)/TCP(sport = client_port, flags = 'A', dport = server_port, seq =finack.ack, ack = finack.seq + 1 )
send(ackack)

