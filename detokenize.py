import sys
import os
from hashlib import md5
from binascii import hexlify, unhexlify
from Crypto.Cipher import ARC4
from rc4 import CustomRC4

def CryptDeriveKey(passphrase):
    """
        Stupid MS-specific method of deriving session key from passphrase
        https://stackoverflow.com/questions/18093316/ms-cryptoapi-giving-wrong-rc4-results
    """
    return md5(passphrase).digest()[:5] + b'\x00'*11 

class KixtartInstruction:

    def __init__(self, raw):
        self.raw = bytearray(raw)
        assert self.raw[0] == 0xEC
        
        
class Kixtart:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as fp:
            self.data = bytearray(fp.read())
        self.header = self.data[:6]
        #TODO one of these bytes should actually indicate if it is encrypted or not
        if self.header != b'\x1a\xaf\x06\x00\x00\x10':
            raise Exception(f'Unrecognized header {hexlify(self.header)}')
        self.key = self.data[0x06:0x16]
        self.session_key = CryptDeriveKey(self.key)
        self.ciphertext = self.data[0x16:]
        
    def decrypt(self):
        arc4 = ARC4.new(key=self.session_key, drop=0)
        print(f'decrypting ciphertext: {hexlify(self.ciphertext[:8])}...')
        self.tokenized = arc4.decrypt(self.ciphertext)
        #if self.plaintext[:4] != b'\x34\x01\x00\x00':
        #    raise Exception(f'Failed to decrypt')
        self.parse()
        return self.tokenized

    def parse_instr(self, instr):
        if instr[0] != 0xEC:
            #raise Exception('Instruction does not start with 0xEC')
            print('Instruction does not start with 0xEC')
        line = instr[1]
        var_name_type = instr[2]
        ptr = 3
        if var_name_type == 0xdf:
            var_name = ""
            while instr[ptr] != 00:
                var_name.append(chr(instr[ptr]))
                ptr += 1
        ptr += 1
         
        
     
    def parse(self):
        operators = {0x00: ' and ', 0x08: 'cls', 0x0F: 'do ', 0x15: 'exit ', 0x19: 'For ', 0x1B: 'get ', 0x1F: 'gosub ', 0x26: 'loop', 0x2B: 'Not ', 0x2C: ' or ', 0x40: ' To ', 0x41: 'until ',  0xD1: ' = ', 0xC6: ' + ', 0xCC: ', ', 0xCD: '(', 0xCE: ') ', 0x21: 'if ', 0x13: 'endselect', 0x14: 'else', 0x03: 'break ', 0xC5: ' / ', 0xCF: '[', 0xD0: ']', 0x2A: 'Next', 0xE4: '? ', 0x11: 'endif', 0xD7: ' <> ', 0x10: 'each ', 0x22: ' in ', 0x36: 'select', 0x05: 'case ', 0x43: 'while ', 0xD4: '<=', 0xD5: '>='}
        #keywords = {0x07: 'at ', 0x20: 'exist', 0x2A: 'GetObject', 0x3F: 'CreateObject', 0x48: 'rnd'}
        keywords = {0x00:"abs",
                    0x01:"asc",
                    0x02:"ascan",
                    0x03:"addkey",
                    0x04:"addprinterconnection",
                    0x05:"addprogramgroup",
                    0x06:"addprogramitem",
                    0x07:"at",
                    0x08:"backupeventlog",
                    0x09:"box",
                    0x0b:"chr",
                    0x0c:"cint",
                    0x0d:"cleareventlog",
                    0x0e:"close",
                    0x0f:"comparefiletimes",
                    0x10:"cstr",
                    0x11:"dectohex",
                    0x12:"delkey",
                    0x13:"delprogramgroup",
                    0x14:"delprogramitem",
                    0x15:"deltree",
                    0x16:"delvalue",
                    0x17:"delprinterconnection",
                    0x18:"dir",
                    0x19:"enumgroup",
                    0x1a:"enumipinfo",
                    0x1b:"enumkey",
                    0x1c:"enumlocalgroup",
                    0x1d:"enumvalue",
                    0x1e:"execute",
                    0x1f:"existkey",
                    0x20:"exist",
                    0x21:"expandenvironmentvars",
                    0x22:"fix",
                    0x23:"formatnumber",
                    0x24:"freefilehandle",
                    0x25:"getdiskspace",
                    0x26:"getfileattr",
                    0x27:"getfilesize",
                    0x28:"getfiletime",
                    0x29:"getfileversion",
                    0x2a:"getobject",
                    0x2b:"iif",
                    0x2c:"ingroup",
                    0x2d:"instr",
                    0x2e:"instrrev",
                    0x2f:"int",
                    0x30:"isdeclared",
                    0x31:"join",
                    0x32:"kbhit",
                    0x33:"keyexist",
                    0x34:"lcase",
                    0x35:"left",
                    0x36:"len",
                    0x37:"loadkey",
                    0x38:"loadhive",
                    0x39:"logevent",
                    0x3a:"logoff",
                    0x3b:"ltrim",
                    0x3c:"makearray",
                    0x3d:"memorysize",
                    0x3e:"messagebox",
                    0x3f:"createobject",
                    0x40:"open",
                    0x41:"readprofilestring",
                    0x42:"readline",
                    0x43:"readtype",
                    0x44:"readvalue",
                    0x45:"redirectoutput",
                    0x46:"right",
                    0x47:"rnd",
                    0x48:"round",
                    0x49:"rtrim",
                    0x4a:"savekey",
                    0x4b:"sendkeys",
                    0x4c:"sendmessage",
                    0x4d:"setascii",
                    0x4e:"setconsole",
                    0x4f:"setdefaultprinter",
                    0x50:"setfocus",
                    0x51:"setfileattr",
                    0x52:"setoption",
                    0x53:"setsystemstate",
                    0x54:"settitle",
                    0x55:"setwallpaper",
                    0x56:"showprogramgroup",
                    0x57:"shutdown",
                    0x58:"sidtoname",
                    0x59:"substr",
                    0x5a:"srnd",
                    0x5b:"split",
                    0x5c:"trim",
                    0x5d:"ubound",
                    0x5e:"ucase",
                    0x5f:"unloadhive",
                    0x60:"val",
                    0x61:"vartype",
                    0x62:"vartypename",
                    0x63:"writeline",
                    0x64:"writeprofilestring",
                    0x65:"writevalue",
                    0x66:"getcommandline"}
        macros = {0x01: 'address', 0x02: 'build', 0x04: 'comment', 0x05: 'cpu', 0x07: 'csd', 0x08: 'curdir', 0x09: 'date', 0x0a: 'day', 0x0B: 'domain', 0x0C: 'dos', 0x0D: 'error', 0x0E: 'serror', 0x0F: 'fullname', 
                   0x10: 'homedir', 0x11: 'homedrive', 0x12: 'homeshr', 0x14: 'im', 0x15: 'IpAddress0', 0x16: 'IpAddress1', 0x17: 'IpAddress2', 0x18: 'IpAddress3', 0x19: 'inwin', 0x1A: 'kix', 0x1B: 'kq', 0x1C: 'lanroot', 0x1D: 'ldomain', 0x1E: 'ldrive', 0x1F: 'lm', 
                   0x20: 'logonmode', 0x21: 'longhomedir', 0x22: 'lserver', 0x23: 'm0', 0x24: 'monthno', 0x25: 'maxpwage', 0x26: 'msecs', 0x29: 'primarygroup', 0x2A: 'priv', 0x2B: 'productsuite', 0x2C: 'producttype', 0x2D: 'pwage', 0x2E: 'ras',
                   0x30: 'rserver', 0x31: 'scriptdir', 0x33: 'scriptname', 0x34: 'sid', 0x35: 'site', 0x36: 'startdir', 0x37: 'syslang', 0x39: 'time', 0x3B: 'userid', 0x3C: 'userlang', 0x3D: 'wdayno', 0x3E: 'wksta', 0x3F: 'wuserid',
                   0x40: 'xt', 0x41: 'ydayno', 0x42: 'year', 0xFF: '???'}
        self.script = ['']*1000
        self.code_length = int.from_bytes(self.tokenized[:4], byteorder='little')
        labels_offset = self.code_length + 4
        labels_length = int.from_bytes(self.tokenized[labels_offset:labels_offset+4], byteorder='little')
        self.labels = self.tokenized[labels_offset+4:labels_offset+4+labels_length].split(b'\x00')
        print(self.labels)
        vars_offset = labels_offset + labels_length + 4
        self.vars_length = int.from_bytes(self.tokenized[vars_offset:vars_offset+4], byteorder='little')
        self.variables = self.tokenized[vars_offset+4:vars_offset+4+self.vars_length].split(b'\x00')
        print(self.variables)
        i = 4
        line_num = 0
        while True:
            if self.tokenized[i] == 0xEC:
                #denotes a new line
                line_num = self.tokenized[i+1]
                #print(f'Parsing line {line_num}')
                i += 2
                continue
            if self.tokenized[i] == 0xDF:
                #variable - name inline
                i += 1
                name = '$'
                while self.tokenized[i] != 0:
                    name += chr(self.tokenized[i])
                    i += 1
                self.script[line_num] += name
                i += 1
                continue
            """
            if self.tokenized[i] == 0x43:
                # label
                if self.tokenized[i+1] == 0xDA:
                    # labels seem to be indexed from 1 for some reason?
                    label = self.labels[self.tokenized[i+2]-1].decode('utf-8')
                    print(f'labels[{self.tokenized[i+2]}] = {label}')
                    self.script[line_num] += ':' + label 
                    i += 3
                else:
                    print(f'Unable to parse label: {hexlify(self.tokenized[i:i+3])}')
                    self.script[line_num] += ':???'
                    i += 3
                continue
            """
                
            if self.tokenized[i] in operators:
                self.script[line_num] += f'{operators[self.tokenized[i]]}'
                i += 1
                continue
            if self.tokenized[i] == 0xDA:
                #int const
                self.script[line_num] += str(self.tokenized[i+1])
                i += 2
                continue
            if self.tokenized[i] == 0xDB:
                # 2 byte int
                self.script[line_num] += str(int.from_bytes(self.tokenized[i+1:i+3], byteorder='little'))
                i += 3
                continue
            if self.tokenized[i] == 0xDE:
                # string literal in-line
                i += 1
                name = ''
                while self.tokenized[i] != 0:
                    name += chr(self.tokenized[i])
                    i += 1
                self.script[line_num] += f'"{name}"'
                i += 1
                continue
            if self.tokenized[i] == 0xE7:
                # Fetch variable name from vars table
                #TODO is this null terminated or 2 bytes?
                offset = int.from_bytes(self.tokenized[i+1:i+3], byteorder='little')
                self.script[line_num] += '$' + self.variables[offset].decode('utf-8')
                i += 3
                continue
            if self.tokenized[i] == 0xE8:
                # object method -  Fetch method name from vars table
                #TODO is this null terminated or 2 bytes?
                offset = int.from_bytes(self.tokenized[i+1:i+3], byteorder='little')
                self.script[line_num] += '.' + self.variables[offset].decode('utf-8')
                i += 3
                continue
            if self.tokenized[i] == 0xE9:
                # Fetch variable name from vars table
                #TODO is this null terminated or 2 bytes?
                offset = int.from_bytes(self.tokenized[i+1:i+3], byteorder='little')
                self.script[line_num] += self.variables[offset].decode('utf-8')
                i += 3
                continue
            if self.tokenized[i] == 0xEA:
                if self.tokenized[i+1] in keywords:
                    self.script[line_num] += keywords[self.tokenized[i+1]]
                else:
                    print(f'Unrecognized keyword 0x{self.tokenized[i+1]:02X}')
                    self.script[line_num] += '???'
                i += 2
                continue

            if self.tokenized[i] == 0xE0:
                if self.tokenized[i+1] in macros:
                    self.script[line_num] += '@' + macros[self.tokenized[i+1]]
                else:
                    print(f'unrecognized @ var 0x{self.tokenized[i+1]:02X}')
                    self.script[line_num] += '@???'
                i += 2
                continue
                
                
            if self.tokenized[i] == 0xF1:
                return 
            print(f'Failed to parse token {self.tokenized[i]:02X} in {hexlify(self.tokenized[i-2:i+3])}')
            return
            
                
                
            
        for instr in self.tokenized[4::8]:
            try:
                instr = bytearray(instr)
                print(self.parse_instr(instr))
            except:
                pass
            
    
    def print(self):
        print(f'Code length: 0x{self.code_length:04X}')

for arg in sys.argv[1:]:
    kix = Kixtart(arg)
    kix.decrypt()
    print(hexlify(kix.tokenized))
    kix.print()
    print()
    print('SCRIPT:')
    for line in kix.script:
        if line:
            print(line)
    
