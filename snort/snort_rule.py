import re
import random
import os
class Snort_Rule():
    rule_actions = ['alert','block','drop','log','pass']
    rule_protocols = ['ip','icmp','tcp','udp']
    rule_gen_opts = ['msg:','reference:','gid:','sid:','rev:','classtype:','priority:','metadata:service','metadata:','content:','distance:','base64_decode:','base64_data','isdataat:','flow:','within:']
    IP_RE      = re.compile(r"(!){0,1}(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d|(?:\.\d))(?!\/)")
    IP_CIDR_RE = re.compile(r"(!){0,1}(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}(?!\d|(?:\.\d))")
    #Will take the last 5 characters of a digit string if the digit is longer than 5
    PORT_RE = re.compile(r"(!){0,1}(:){0,1}([1-9]){1}([0-9]){0,4}(?!\d)(:){0,1}(([1-9]){1}([0-9]){0,4}(?!\d)){0,1}")
    RULE_RE = re.compile(r"(alert|block|drop|log|pass)(.+)(\))")
    RC_RE = re.compile(r"(\(.?+\))")

    def __init__(self,input, config):
        rules = None
        #line below defined rule names twice, made things weird. temp removal for testing purposes.
        #self.rules = {}
        #Defining as a list
        self.rules = []
        self.rule_name = ''

        self.ip_vars = {}
        self.port_vars = {}
        self.my_pcap = None
        self.__set_vars__(config)
        rules = re.findall(self.RULE_RE,input)
        
        for i in rules:
            rh = self.__get_rule_header__(''.join(i))
            rp = self.__get_rule_params__(''.join(i))
            vl = [rh,rp]
            self.rule_name = self.__get_rule_name__(''.join(i))
            #temp removal from the double naming convention times
            #vlus = {self.__get_rule_name__(''.join(i)):vl}
            #self.rules.update(vlus)
            self.rules=vl
            
    def __get_rule_params__(self, rule):
        content = re.search(r'(\(.+?\))', rule).group()
        content = content[1:len(content)-1].split(';')
        services = []
        flow = None
        #Go through the meat of the rule. Sanitize each rule so related parameters stay related.
        for start,element in enumerate(content):
            dojoin=True
            for gen_opt in self.rule_gen_opts:
                tst = element.strip()
                if tst.startswith(gen_opt):
                    dojoin=False
            if dojoin:
                newvar = ";"+element
                content[start] = newvar
                content[start-1:start] = [''.join(content[start-1:start])]
            #strip leading whitespace to tokenize
            if content[start].startswith(' '):
                content[start] = content[start][1:]    
        for param in content:
            for i in self.rule_gen_opts:
                if param.lower().startswith(i):
                    chunk = len(i)
                    if param[len(i):len(i)+1] == ' ':
                        chunk =  chunk + 1                
                    services.append({i:param[chunk:]})
                    
                    
                    break
        return services
        
    def __get_rule_name__(self,rules_list):
        try:
            return re.search(r'(reference:)(.+?)(\;){1}',rules_list).group().strip(';').replace('reference:','')
                 
        except:
            return re.search(r'(msg:)(.+?)(\;){1}',rules_list).group().strip(';').replace('msg:','')  
            
            
    def return_name(self):
        return self.rule_name
        #return list(self.rules.keys())[0]

    def __set_vars__(self,config):
        if config is None:
            return
        config_dump = None
        with open(config,'r') as f:
            config_dump = f.readlines()
            f.close()
        for line in config_dump:
            if line.lower().startswith('ipvar'):
                rule_var_params = line.split()
                rule_var_params[1] = rule_var_params[1].upper()
                if not rule_var_params[1].startswith('$'):
                    rule_var_params[1] = '$' + rule_var_params[1]
                
                if rule_var_params[2] in self.ip_vars.keys():
                    self.ip_vars.update({rule_var_params[1]:self.ip_vars[rule_var_params[2]]})
                elif rule_var_params[2]:
                    if '[' in rule_var_params[2]:
                        rule_var_params[2] = rule_var_params[2].strip('[').strip(']')
                        rule_var_params[2] = rule_var_params[2].split(',') 
                        for count,elem in enumerate(rule_var_params[2]):
                            if elem in self.port_vars.keys():
                                rule_var_params[2][count] = self.port_vars[rule_var_params[2][count]]
                    self.ip_vars.update({rule_var_params[1]:rule_var_params[2]})
            elif line.lower().startswith('portvar'):
                rule_var_params = line.split()
                if not rule_var_params[1].startswith('$'):
                    rule_var_params[1] = '$' + rule_var_params[1]
                if rule_var_params[2] in self.port_vars.keys():
                    self.port_vars.update({rule_var_params[1]:self.port_vars[rule_var_params[2]]})
                elif rule_var_params[2]:
                    if '[' in rule_var_params[2]:
                        rule_var_params[2] = rule_var_params[2].strip('[').strip(']')
                        rule_var_params[2] = rule_var_params[2].split(',') 
                        for count,elem in enumerate(rule_var_params[2]):
                            if elem in self.port_vars.keys():
                                rule_var_params[2][count] = self.port_vars[rule_var_params[2][count]]
                            else:
                                rule_var_params[2][count] = int(rule_var_params[2][count])                
                    self.port_vars.update({rule_var_params[1]:rule_var_params[2]})
    
    def __get_rule_header__(self, rule):

        rule_params = rule.split('(')
        rule_params = rule_params[0].split(' ')
        rule_action = None
        rule_ip_src = None
        rule_src_p = rule_params[3]
        rule_direction = None
        rule_ip_dst = None
        rule_dst_p = rule_params[6]

        if len(rule_params) < 2:
            raise Exception("Rule is not defined...")
        
        if rule_params[0].lower() in 'ruletype':
            raise Exception("\'ruletype\' is not supported, Skipping...")
        if rule_params[0].lower() in self.rule_actions:
            rule_action = rule_params[0]
        else:
            raise Exception("No Rule Action Found, Skipping...")
        if rule_params[1].lower() in self.rule_protocols:
            rule_protocol = rule_params[1].lower()
        else:
            raise Exception("No Rule Protocol Found, Skipping...")
        if rule_params[2].upper() in self.ip_vars:
            rule_ip_src = self.ip_vars[rule_params[2]]
        elif self.IP_CIDR_RE.match(rule_params[2]) or self.IP_RE.match(rule_params[2]):
            rule_ip_src = rule_params[2]
        else:
            raise Exception("No Rule Source IP Found. Do you have an undefined ipvar? Skipping...")
        if rule_params[4] in '->' or rule_params[4] in '<>':
            rule_direction = rule_params[4]
        else:
            raise Exception("No Rule Directionality Found, Skipping...")
        if rule_params[5].upper() in self.ip_vars:
            rule_ip_dst = self.ip_vars[rule_params[5]]
        elif self.IP_CIDR_RE.match(rule_params[5]) or self.IP_RE.match(rule_params[5]):
            rule_ip_dst = rule_params[5]
        else:
            raise Exception("No Rule Dest IP Found. Do you have an undefined ipvar? Skipping...")
        return {'rule_action':rule_action,'protocol':rule_protocol, 'rule_ip_src':rule_ip_src,'rule_src_p':rule_src_p,'rule_direction':rule_direction,'rule_ip_dst':rule_ip_dst,'rule_dst_p':rule_dst_p}
        
    def get_pcap_build_struct(self):
        if self.my_pcap is None:
            self.build_pcap()
        return self.my_pcap
   
    def build_pcap(self):
        return 0
