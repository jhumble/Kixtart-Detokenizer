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
        operators = {0x19: 'For ', 0x40: ' To ', 0xD1: ' = ', 0xC6: ' + ', 0xCC: ', ', 0xCD: '(', 0xCE: ')', 0x21: 'if ', 0x14: 'else', 0x03: 'break ', 0xC5: ' / ', 0x2A: 'Next', 0xE4: '? ', 0x11: 'endif', 0xD7: ' <> ', 0x10: 'each ', 0x22: ' in ', 0x36: 'select', 0x05: 'case'}
        keywords = {0x20: 'exist', 0x2A: 'GetObject', 0x3F: 'CreateObject', 0x48: 'rnd'}
        macros = {0x01: 'address', 0x02: 'build', 0x04: 'comment', 0x05: 'cpu', 0x07: 'csd', 0x08: 'curdir', 0x09: 'date', 0x0a: 'day', 0x0B: 'domain', 0x0C: 'dos', 0x0D: 'error', 0x0E: 'serror', 0x0F: 'fullname', 
                   0x10: 'homedir', 0x11: 'homedrive', 0x12: 'homeshr', 0x14: 'im', 0x15: 'IpAddress0', 0x16: 'IpAddress1', 0x17: 'IpAddress2', 0x18: 'IpAddress3', 0x19: 'inwin', 0x1A: 'kix', 0x1B: 'kq', 0x1C: 'lanroot', 0x1D: 'ldomain', 0x1E: 'ldrive', 0x1F: 'lm', 
                   0x20: 'logonmode', 0x21: 'longhomedir', 0x22: 'lserver', 0x23: 'm0', 0x24: 'monthno', 0x25: 'maxpwage', 0x26: 'msecs', 0x29: 'primarygroup', 0x2A: 'priv', 0x2B: 'productsuite', 0x2C: 'producttype', 0x2D: 'pwage', 0x2E: 'ras',
                   0x30: 'rserver', 0x31: 'scriptdir', 0x33: 'scriptname', 0x34: 'sid', 0x35: 'site', 0x36: 'startdir', 0x37: 'syslang', 0x39: 'time', 0x3B: 'userid', 0x3C: 'userlang', 0x3D: 'wdayno', 0x3E: 'wksta', 0x3F: 'wuserid',
                   0x40: 'xt', 0x41: 'ydayno', 0xFF: '???'}
        self.script = ['']*1000
        self.code_length = int.from_bytes(self.tokenized[:4], byteorder='little')
        vars_offset = self.code_length + 8
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
            print(f'Failed to parse token {self.tokenized[i]:02X} in {hexlify(self.tokenized[i-2:i+2])}')
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
    
