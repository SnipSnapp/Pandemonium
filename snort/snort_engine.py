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

        print(self.rule_files)
        self.__parse_rule_files__()
       
    def __parse_rule_files__(self):
        for rule_f in self.rule_files:
            rulez = []
            if os.path.exists(rule_f):
                with open(rule_f,'r') as f:
                    rulez = f.read()
                    f.close
                matches = re.findall(self.RULE_MATCH,rulez)
                for x in matches:
                    self.rules.update({x:Snort_Rule(''.join(x),self.config)})
                exit(0)
            else:
                print("PATH DNE")
                exit(0)
            
