import re
import random
import snort_rule
class Snort_Engine():
    rule_actions = ['alert','block','drop','log','pass']
    rule_protocols = ['ip','icmp','tcp','udp']
    IP_RE      = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d|(?:\.\d))")
    IP_CIDR_RE = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))")
    def __init__(self, database,config):
        self.folder = database
        self.rules = {}
        self.config = config
        self.variables = {}
        for (dirpath,dirnames,filenames) in os.walk(self.folder):
            if filenames.lower().endswith('.conf') or filenames.lower().endswith('.config'):
                self.config = dirpath + '/'+ filenames
            elif filenames.lower().endswith('.rules') or filenames.lower().endswith('.snort'):
                self.rules.update({dirpath + '/' + filenames:None})
        

    def __parse_config_file__(self):
        if self.config is None:
            return
        config_dump = None
        with open(self.config,'r') as f:
            config_dump = f.readlines
            f.close()
        for line in config_dump:
            line = "ok"
            if line.lower().startswith('ipvar'):
                rule_var_params = line.split()
                if rule_var_params[1] in self.variables:
                    self.variables.update({rule_var_params[1]:self.variables(rule_var_params[1])})
                elif rule_var_params[2]:
                    self.variables.update({rule_var_params[1]:rule_var_params[2]})


        
    
    def __set_rule_params__(self, fname):
        fnames = self.rules.keys()
        for key in fnames:
            self.rules.updates({key:self.__get_rule_contents__(key)})


    def __get_rule_contents__(self,key):
        file_contents = None
        with open(key,'r') as f:
            file_contents = f.read()
            f.close
        rule_header = __get_rule_header__(file_contents)



    def __get_rule_header__(self, rule):
        rule_params = rule.split(' ')
        rule_action = None
        rule_ip_src = None
        rule_src_p = rule_params[3]
        rule_direction = None
        rule_ip_dst = None
        rule_dst_p = rule_params[6]
        if len(rule_params) < 7:
            raise Exception("Rule is not defined...")

        if rule_params[0].lower in self.rule_actions:
            rule_action = rule_params[0]
        else:
            raise Exception("No Rule Action Found, Skipping...")
        if rule_params[1].lower in self.rule_protocols:
            rule_protocol = rule_params[1].lower
        else:
            raise Exception("No Rule Protocol Found, Skipping...")
        if rule_params[2].lower() in self.variables:
            rule_ip_src = self.variables(rule_params[2])
        elif self.IP_CIDR_RE.match(rule_params[2]) or self.IP_RE.match(rule_params[2]):
            rule_ip_src = rule_params[2]
        else:
            raise Exception("No Rule Source IP Found. Do you have an undefined ipvar? Skipping...")
        if rule_params[4] in '->' or rule_params[4] in '<>':
            rule_direction = rule_params[4]
        else:
            raise Exception("No Rule Directionality Found, Skipping...")
        if rule_params[5].lower() in self.variables:
            rule_ip_dst = self.variables(rule_params[5])
        elif self.IP_CIDR_RE.match(rule_params[5]) or self.IP_RE.match(rule_params[5]):
            rule_ip_dst = rule_params[5]
        else:
            raise Exception("No Rule Dest IP Found. Do you have an undefined ipvar? Skipping...")
        
        
            
        
            
        


        
    
