from Snort.snort_engine import Snort_Engine
import argparse
import os
import re

IP_REGEX = re.compile('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
MAC_REGEX = re.compile('^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
MASTER_IP = None
MASTER_MAC = None
SLAVE_IP = None
SLAVE_MAC = None
MS_PORT = '13101'
MS_DIGIT = re.compile('\d*')


parser = argparse.ArgumentParser(description='Snort rule player. Test snort rules over the wire without a pcap!')
parser.add_argument('-Srf','--Snort_rules_folder', help='Path to Snort rules folder.', default='./Rules')
parser.add_argument('-Scfg','--Snort_config_file',help='Path to Snort config file.', default='./Snort/config/Snort_config.txt')
parser.add_argument('-Sm','--Signature_mode',help='The type of signature you are using. THIS ONLY USES SNORT FOR NOW. YARA IS FUTURE, POST SNORT',default='Snort',choices=['Yara','Snort'])
parser.add_argument('-MoS', '--Sender_MAC_Address', help='The MAC address of the sender.[XX:XX:XX:XX:XX:XX]', default='RANDOM')
parser.add_argument('-MoR', '--Receiver_MAC_Address',help='The MAC address of the receiver.[XX:XX:XX:XX:XX:XX]',default='RANDOM')
parser.add_argument('-IoR', '--Receiver_IP_Address',help='The IP address of the receiver.[XXX.XXX.XXX.XXX]',default='RANDOM')
parser.add_argument('-IoS', '--Sender_IP_Address',help='The IP address of the Sender.[XXX.XXX.XXX.XXX]',default='RANDOM')
parser.add_argument('-SC','--Send_Count',help='The number of times to send a signature. Default is 6 due to testing.',default='6' )
parser.add_argument('-r','--run_all_signatures', default='True')
parser.add_argument('-M','--set_as_master',help="Sets this host as the master, signatures will be sent to a designated slave. The slave is the \'server\' in the transaction. This host will act as a client.", default='False')
parser.add_argument('-S','--set_as_slave',help="Sets this host as the slave, signatures will be received from its master. The slave is the \'server\' in the transaction. This host will act as server.", default='False')
parser.add_argument('-B', '--broadcast_mode', help="Send all traffic as broadcast", default="False")
def print_bad_opt():
    parser.print_help()
    exit(0)
def get_SI(MoS,MoR,IoR,IoS,SC, ENG:Snort_Engine,bcast=None):
    UI='no'
    print('We tried')
    
    while 'exit' not in UI.lower():
        UI=input('Select:\n\tRule item:[x]\n\tRule Range:[x-xxx]\n\tChange Source IP:SRC_IP=[XXX.XXX.XXX.XXX]\n\tChange Dest IP:DST_IP=[XXX.XXX.XXX.XXX]\n\tChange Source MAC:SRC_MAC=[XX:XX:XX:XX:XX:XX]\n\tChange Dest MAC:DST_MAC=[XX:XX:XX:XX:XX:XX]\n\tChange Send Count:CNT=[x]\n\tList Signatures:ls\n\tPlay All:all\n\tExit:exit\n\t>$:')
        UI = UI.upper()
        if '=' in UI:
            if 'SRC_MAC' in UI :
                MoS=UI.split('=')[1]
            elif 'DST_MAC' in UI :
                MoR = UI.split('=')[1]
            elif 'SRC_IP' in UI :
                IoS = UI.split('=')[1]
            elif 'DST_IP' in UI :
                IoR = UI.split('=')[1]
            elif 'CNT' in UI:
                SC=UI.split('=')[1]
        else:
            ENG.play_pcap(MoS,MoR,IoR,IoS,SC,UI,bcast=bcast)
def set_master_setting():
    global MAC_REGEX
    global IP_REGEX
    global SLAVE_MAC
    global SLAVE_IP
    global MS_PORT
    while SLAVE_IP is None or (SLAVE_IP.lower() != 'exit'and not IP_REGEX.match(SLAVE_IP)):
        SLAVE_IP = input("Set the IP Address of the slave ('exit' to exit):\n").strip('\r').strip('\n')
    if SLAVE_IP.lower() == 'exit':
        print('detected exit-case. Exiting.')
        exit(0)
    print(SLAVE_IP + " set as slave IP address.")
    SLAVE_MAC = input('Would you like to enter a MAC address for the slave? If you don\'t the slave will be accessed using broadcast mode <WARNING MAY CAUSE BROADCAST STORM>. (\'y/n\')\n').strip('\r').strip('\n').lower()
    while SLAVE_MAC is None or SLAVE_MAC.startswith('y') or (SLAVE_MAC.lower() != 'exit' and not MAC_REGEX.match(SLAVE_MAC)):
        SLAVE_MAC = input('Enter the MAC address associated with the IP of the slave:\n')
    
    enter_new_port = input(f'Would you like to enter in a non-default port for the slave & Master (they both receive on same port) to receive instructions? (y/n)?\n\tDefault port is {SLAVE_PORT}. \n').lower().strip('\r').strip('\n')
    if enter_new_port.startswith('y'):
        MS_PORT = input('Enter a valid port (PORT<65535):\n').strip('\r').strip('\n')
        while not MS_DIGIT.match(MS_PORT):
            MS_PORT = input('Enter a valid port (PORT<65535):\n').strip('\r').strip('\n')
def set_slave_setting():
    global MAC_REGEX
    global IP_REGEX
    global MASTER_MAC
    global MASTER_IP
    global MS_PORT
    while MASTER_IP is None or (MASTER_IP.lower() != 'exit'and not IP_REGEX.match(MASTER_IP)):
        MASTER_IP = input("Set the IP Address of the Master ('exit' to exit):\n").strip('\r').strip('\n')
    if SLAVE_IP.lower() == 'exit':
        print('detected exit-case. Exiting.')
        exit(0)
    print(SLAVE_IP + " set as Master IP address.")
    SLAVE_MAC = input('Would you like to enter a MAC address for the Master? If you don\'t the slave will accept any master with the designated IP. (\'y/n\')\n').strip('\r').strip('\n').lower()
    while SLAVE_MAC is None or MASTER_MAC.startswith('y') or (SLAVE_MAC.lower() != 'exit' and not MAC_REGEX.match(SLAVE_MAC)):
        SLAVE_MAC = input('Enter the MAC address associated with the IP of the Master:\n')
    
    enter_new_port = input(f'Would you like to enter in a non-default port for the slave & Master (they both receive on same port) to receive instructions? (y/n)?\n\tDefault port is {SLAVE_PORT}. \n').lower().strip('\r').strip('\n')
    if enter_new_port.startswith('y'):
        MS_PORT = input('Enter a valid port (PORT<65535):\n').strip('\r').strip('\n')
        while not MS_DIGIT.match(MS_PORT) and (int(MS_DIGIT) < 0 or int(MS_DIGIT) > 65534):
            MS_PORT = input('Enter a valid port (PORT<65535):\n').strip('\r').strip('\n')





            
if __name__ == '__main__':
    
    args = parser.parse_args()
    if args.Signature_mode in 'Snort':
        if not os.path.exists(args.Snort_rules_folder):
            print("The path doesn't exist to the snort rules folder.\n Please ensure the folder \'./Rules exists\'")
            print_bad_opt()
        elif not os.path.exists(args.Snort_config_file):
            print("The \'snort_config.txt\' file was not found inside of the folder \'./config\'.\n Please ensure the file exists with your snort configuration.")
            print_bad_opt()
        else:
            bcastt=None
            if args.broadcast_mode != 'False':
                bcastt = True
            if args.set_as_master != 'False':
                print('Setting this host as master. Configure master settings...')
                set_master_setting()
            elif args.set_as_slave != 'False':
                print('Setting this host as slave. Configure slave settings...')
                set_slave_setting()                
            print("creating engine..")
            if 'T' in args.run_all_signatures:
                sn = ENG=Snort_Engine(rule_folder=args.Snort_rules_folder,config=args.Snort_config_file)

                sn.play_pcap(args.Sender_MAC_Address,args.Receiver_MAC_Address,args.Receiver_IP_Address,args.Sender_IP_Address,args.Send_Count,'all', bcast=bcastt)
                exit(0)
            else:
                get_SI(args.Sender_MAC_Address,args.Receiver_MAC_Address,args.Receiver_IP_Address,args.Sender_IP_Address,args.Send_Count, ENG=Snort_Engine(rule_folder=args.Snort_rules_folder,config=args.Snort_config_file),bcast=bcastt)
        
    elif args.Signature_mode in 'Yara':
        if not (os.path.exists(args.Yara_rules_folder)):
            print_bad_opt()
    exit(0)
