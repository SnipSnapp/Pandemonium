import re
import os
from .snort_rule import Snort_Rule

class Snort_Engine():
    rule_actions = ['alert','block','drop','log','pass']
    rule_protocols = ['ip','icmp','tcp','udp']
    IP_RE      = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d|(?:\.\d))")
    IP_CIDR_RE = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))")
    RULE_MATCH = r"(alert|log|pass|drop|reject|sdrop){1}(.+)(->|<>)(.+)(\))"

    def __init__(self, rule_folder:str, config:str):
        self.rules = {}
        self.config = config
        self.rule_files = os.listdir(rule_folder)
        if not rule_folder.endswith('/'):
            rule_folder = rule_folder + '/'
        for count,fname in enumerate(self.rule_files):
            self.rule_files[count] = rule_folder + fname
        print("parsing rules...")
        self.__parse_rule_files__()
        self.rules_list = list(self.rules.keys())
        self.__select_rule__()


    def __parse_rule_files__(self):
        for rule_f in self.rule_files:
            rulez = []
            if os.path.exists(rule_f):
                with open(rule_f,'r') as f:
                    rulez = f.read()
                    f.close
                matches = re.findall(self.RULE_MATCH,rulez)
                for x in matches:
                    rl = Snort_Rule(''.join(x),self.config)
                    increment = 0
                    rname = rl.return_name()
                    while rname in self.rules:
                        increment +=1
                        rname = rl.return_name() +'-'+ str(increment)

                    self.rules.update({rname:rl})
                    print("parsed rule: " + rname)
                    #self.rules.update({x:Snort_Rule(''.join(x),self.config)})
                print("parsed rule file: " + rule_f)
            else:
                print("Snort rule file path DNE: " + rule_f)
                exit(0)
           
            
    def __select_rule__(self):
        self.play_pcap(self.rules)

    def play_pcap(self, rule):
        
        rule_definition = self.rules['bugtraq,57842'].rules
        print(rule_definition[0])
        
        exit(0)
