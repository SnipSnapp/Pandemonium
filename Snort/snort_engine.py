import re
import os
import time
from .snort_rule import Snort_Rule
from .traffic_player import traffic_player
import copy
class Snort_Engine():
    rule_actions = ['alert','block','drop','log','pass']
    rule_protocols = ['ip','icmp','tcp','udp']
    IP_RE      = re.compile(r'(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d|(?:\.\d))')
    IP_CIDR_RE = re.compile(r'(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))')
    RULE_MATCH = r'(alert|log|pass|drop|reject|sdrop){1}(.+)(->|<>)(.+)(\))'

    def __init__(self, rule_folder:str, config:str):
        self.rules = {}
        self.config = config

        self.rule_files = os.listdir(rule_folder)
        if not rule_folder.endswith('/'):
            rule_folder = rule_folder + '/'
        for count,fname in enumerate(self.rule_files):
            self.rule_files[count] = rule_folder + fname
        #print("parsing rules...")
        self.__parse_rule_files__()
        self.rules_list = list(self.rules.keys())
        for cnt,itm in enumerate(self.rules_list):
            print(str(cnt) + '. ' + itm)
        #print(self.rules.keys())
        


    def __parse_rule_files__(self):
        for rule_f in self.rule_files:
            rulez = []
            if os.path.exists(rule_f):
                with open(rule_f,'r') as f:
                    rulez = f.read()
                    f.close
                matches = re.findall(self.RULE_MATCH,rulez)
                for x in matches:
                    try:
                        rl = Snort_Rule(''.join(x),self.config)
                        increment = 0
                        rname = rl.return_name()
                        while rname in self.rules:
                            increment +=1
                            rname = rl.return_name() +'-'+ str(increment)

                        self.rules.update({rname:rl})
                        #print("parsed rule: " + rname)
                        #self.rules.update({x:Snort_Rule(''.join(x),self.config)})
                    except:
                        pass
                print("parsed rule file: " + rule_f)
            else:
                print("Snort rule file path DNE: " + rule_f)
                exit(0)
           
            
    def select_rule(self,src_ip,dst_ip,src_mac,dst_mac,idno):
        self.play_pcap(self.rules)

    def play_pcap(self,MoS,MoR,IoR,IoS,SC,UI):
        
        if '-' in UI:
            numbos = UI.strip().split('-')
            try:
                playone=False
                stop=int(numbos[1])
                start=int(numbos[0])
            except:
                print("INVALID RANGE FORMAT")
                return
        else:
            try:
                start=int(UI.strip())
                start=stop
                playone=True
            except:
                start=0
                stop=len(self.rules_list)
                playone=False
            
        try:
            sc = int(SC)
        except:
            print("INVALID # OF \'PLAYS\' FORMAT.")
            return
        for itemno in self.rules_list[start:stop]:     
            print('************* '+itemno + ' *************')  
            for x in range(sc):
                time.sleep(0.1)
                opt_placehold = copy.deepcopy(self.rules[itemno].rules[1])
                head_placehold =self.rules[itemno].rules[0].copy()
                print(opt_placehold)
                print(head_placehold)
                traffic_player(head_placehold,opt_placehold,MoS,MoR,IoS,IoR).send_traffic() 
            if playone:
                return
            print('**************'+(len(itemno)*'*') + '**************')
        print("done...")
