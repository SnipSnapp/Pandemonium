from Snort.snort_engine import Snort_Engine
import argparse
import os

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
def print_bad_opt():
    parser.print_help()
    exit(0)
def get_SI(MoS,MoR,IoR,IoS,SC, ENG:Snort_Engine):
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
            ENG.play_pcap(MoS,MoR,IoR,IoS,SC,UI)
    

            
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
            print("creating engine..")
            if 'T' in args.run_all_signatures:
                sn = ENG=Snort_Engine(rule_folder=args.Snort_rules_folder,config=args.Snort_config_file)
                sn.play_pcap(args.Sender_MAC_Address,args.Receiver_MAC_Address,args.Receiver_IP_Address,args.Sender_IP_Address,args.Send_Count,'all')
                exit(0)
            else:
                get_SI(args.Sender_MAC_Address,args.Receiver_MAC_Address,args.Receiver_IP_Address,args.Sender_IP_Address,args.Send_Count, ENG=Snort_Engine(rule_folder=args.Snort_rules_folder,config=args.Snort_config_file))
        
    elif args.Signature_mode in 'Yara':
        if not (os.path.exists(args.Yara_rules_folder)):
            print_bad_opt()
    exit(0)
