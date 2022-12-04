from Snort.snort_engine import Snort_Engine
import argparse
import os

parser = argparse.ArgumentParser(description='Snort rule player. Test snort rules over the wire without a pcap!')
parser.add_argument('-Srf','--Snort_rules_folder', help='Path to Snort rules folder.', default='./Rules')
parser.add_argument('-Scfg','--Snort_config_file',help='Path to Snort config file.', default='Snort_config.txt')
parser.add_argument('-Sm','--Signature_mode',help='The type of signature you are using.',default='Snort',choices=['Yara','Snort'])

def print_bad_opt():
    parser.print_help()
    exit(0)

if __name__ == '__main__':
    
    args = parser.parse_args()
    if args.Signature_mode in 'Snort':
        if not (os.path.exists(args.Snort_rules_folder) and os.path.exists(args.Snort_config_file)):
            print_bad_opt()
        else:
            print("creating engine..")
            SN =Snort_Engine(rule_folder=args.Snort_rules_folder,config=args.Snort_config_file)
        
    elif args.Signature_mode in 'Yara':
        if not (os.path.exists(args.Yara_rules_folder)):
            print_bad_opt
    exit(0)
