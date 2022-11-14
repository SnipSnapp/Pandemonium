import re
import random
class Yara_Engine():

    def __init__(self, database):
        self.database=None
        if database is not None:
            self.database=database
        self.keywords = (
            'all','and','any','ascii','at','base64','base64wide','condition',
            'contains','endswith','entrypoint','false','filesize','for','fullword','global',
            'import','icontains','iendswith','iequals','in','include','int16','int16be',
            'int32','int32be','int8','int8be','istartswith','matches','meta','nocase',
            'none','not','of','or','private','rule','startswith','strings',
            'them','true','uint16','uint16be','uint32','uint32be','uint8','uint8be',
            'wide','xor','defined')
    def __parse_rule_file__(self,rule_file):
        rule_name=None
        meta_loc=None
        strings_loc=None
        condition_loc=None
        name_location=0
        rule_strings=[]
        try:
            rule = open(rule_file,'r')
            rule_contents=[]
            rule_contents = rule.readlines
            rule.close()
        except FileNotFoundError:
            print("Yara file was not found. Please validate filename and path.")
        except PermissionError:
            print("Inadequate access rights to file, read-access is necessary to complete operation.")
        rule_name,name_location = self.__get_rule_name_file__(rule_contents)
        meta_loc,strings_loc,condition_loc = self.__find_sections_file__(rule_contents)

    def __parse_rule_arg_section__(self,rule_args):
        rule_args = rule_args.split('=')
        rule_args = rule_args[1]
        relev_args = None
        relev_args = re.findall('"(.*)"',rule_args)[0]
        relev_bytes = bytearray()
        if relev_args is not None:
            relev_args = relev_args.replace('\\r','\r').replace('\\t','\t').replace('\\n','\n').replace('\\\\','\\').replace('\\"','\"')
            post_opts = rule_args.split(relev_args)[1]

            encoding="ascii"
            if 'wide' in post_opts.lower():
                if 'ascii' in post_opts.lower():
                    encoding="utf-16"
                    bytes()
                else:
                    encoding='utf-8'
            if 'unicode' in post_opts.lower():
                encoding = 'unicode'
            relev_args = bytes(relev_args, "utf-8").decode("unicode_escape")
            relev_bytes = bytearray(relev_args,encoding)
        else:
            random.randrange
            relev_args = re.findall('{(.*)}',rule_args)[0]
            rnd_num = random.randrange(48,57)
            rnd_al = random.randrange(65,70)
            replace_char = rnd_al
            if random.randrange(1) == 1:
                replace_char = rnd_num
            str(relev_args).replace('?',str(char(replace_char)))
            
            or_params = re.findall(r'\((.*)\)',relev_args)[0]
            for param in or_params:
                for item in param.split(' '):
                    repl_str = re.match(r'([a-f]|[0-9]){2}',item).join()
                    if re.match(r'([a-f]|[0-9]){2}',item):
                        relev_args = relev_args.replace(param,)




            relev_args = relev_args.split(' ')
            for count,arg in relev_args:
                get_rng = None
                get_rng = re.findall('[(.*)]',arg)[0]
                if get_rng is not None :
                    le_rng = re.findall(r'\d+',get_rng)
                    if le_rng is not None:
                        relev_args.pop(count)
                        for x in range(int(le_rng[0])):
                            relev_args.insert(str(replace_char) + str(replace_char))
                    else:
                        relev_args.pop(count)
            for count,arg in relev_args:
                relev_args[count] = str("\x" + arg).lower
            relev_args = bytes(relev_args, "utf-8").decode("unicode_escape")



                    




                
            





    def __parse_string_section__(self, str_loc,cond_loc,rule_contents):
        str_loc +=1
        string_arg_sections = []
        while str_loc+1 != cond_loc:
            string_arg_sections.append(rule_contents[str_loc])
            str_loc +=1
        

    def __find_sections_file__(self, rule_contents):
        meta_loc=None
        strings_loc=None
        condition_loc=None
        try:
            for x in rule_contents:
                if 'meta:' in x and meta_loc is None:    
                    meta_loc = rule_contents.index(x)
                if 'strings:' in x and strings_loc is None:
                    strings_loc = rule_contents.index(x)
                if 'condition:' in x and condition_loc is None:
                    condition_loc = rule_contents.index(x)    
        except ValueError:
            print("An value error occurred")
        if condition_loc is None:
            raise Exception("No conditions provided in the yara rule")
        return meta_loc,strings_loc,condition_loc


    '''
    Gets the name of a yara rule.
    [Param] rule_name : The contents of a yara file as an array.
    [Return] returns two values, the rule's name, and the rule's file.
    '''
    def __get_rule_name_file__(self, rule_name):
        rule_loc = None
        try:
            for i in rule_name:
                if 'rule' in i:
                    rule_loc = i
                    break
            rule_loc = rule_name.index(rule_loc)
        except ValueError as ve:
            print("Rule is not defined within the yara, ensure a 'rule' exists.")
        rule = rule_name.pop(rule_loc).split(' ')
        if len(rule) < 2:
            raise Exception("No rule name defined. Please define the rule's name.")
        return rule[1], rule_loc
