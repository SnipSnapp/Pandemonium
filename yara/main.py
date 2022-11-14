import os, re
if __name__ == '__main__':
    cwd = os.getcwd()  # Get the current working directory (cwd)
    attempt = [1,2,3,'ok']
    lestr="\\xdz sss "
    print(str(re.match(r'\\',lestr)).join())
    #x=int(lestr.replace("\\x","0x"), 16)
    #print(x)
    bb = bytearray(lestr,'ascii')
    
    print(bb[1])

    exit(0)