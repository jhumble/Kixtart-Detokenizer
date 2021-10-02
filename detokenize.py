import sys
import os
from hashlib import md5
from binascii import hexlify, unhexlify
from Crypto.Cipher import ARC4
from rc4 import CustomRC4
from constants import macros, operators, functions

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
        token_data = arc4.decrypt(self.ciphertext)
        self.code_length = int.from_bytes(token_data[:4], byteorder='little')
        self.tokenized = token_data[4:]
        #if self.plaintext[:4] != b'\x34\x01\x00\x00':
        #    raise Exception(f'Failed to decrypt')
        self.parse()
        return self.tokenized

    def parse_labels(self, data):
        self.labels = {}
        string = ''
        i = 0
        while i < len(data):
            if data[i] == 0:
                idx = int.from_bytes(data[i+1:i+5], byteorder='little')
                self.labels[idx] = string
                string = ''
                i += 5
            else:
                string += chr(data[i])
                i += 1
                
         
        
     
    def parse(self):

        self.script = ['']*1000

        labels_offset = self.code_length
        labels_length = int.from_bytes(self.tokenized[labels_offset:labels_offset+4], byteorder='little')
        print(f'label length: {labels_length:02X}')
        raw_label_data = self.tokenized[labels_offset+4:labels_offset+labels_length]
        print(hexlify(raw_label_data))
        self.parse_labels(raw_label_data)
        
        
        #self.labels = [x for x in self.tokenized[labels_offset+4:labels_offset+4+labels_length].split(b'\x00') if x]
        print(self.labels)
        vars_offset = labels_offset + labels_length + 4
        self.vars_length = int.from_bytes(self.tokenized[vars_offset:vars_offset+4], byteorder='little')
        self.variables = self.tokenized[vars_offset+4:vars_offset+4+self.vars_length].split(b'\x00')
        print(self.variables)
        i = 0
        line_num = 0
        label_count = 0
        buf = self.tokenized
        while True:
            b = buf[i]
            n = buf[i+1]
            # parse line number
            if b in [0xEC, 0xED]:
                # 0xEC - 1 byte line num, 0xED - 2 byte line num
                offset_size = b - 0xEB
                line_num = int.from_bytes(buf[i+1:i+1+offset_size], byteorder='little')
                try:
                    self.script[line_num] += ':' + self.labels[i] + '\n'
                except:
                    # No label for this line
                    pass
                i += 1 + offset_size
                continue
            

            # 1 byte int
            if b == 0xDA:
                self.script[line_num] += str(n)
                i += 2
                continue
            # 2 byte int
            if b == 0xDB:
                self.script[line_num] += str(int.from_bytes(buf[i+1:i+3], byteorder='little'))
                i += 3
                continue
            # String literal - inline
            if b == 0xDE:
                i += 1
                name = ''
                while buf[i] != 0:
                    name += chr(buf[i])
                    i += 1
                self.script[line_num] += f'"{name}"'
                i += 1
                continue
            # Variable name - inline
            if b == 0xDF:
                i += 1
                name = '$'
                while buf[i] != 0:
                    name += chr(buf[i])
                    i += 1
                self.script[line_num] += name
                i += 1
                continue
            # Macro
            if b == 0xE0:
                if n in macros:
                    self.script[line_num] += '@' + macros[n]
                else:
                    print(f'unrecognized @ var 0x{n:02X}')
                    self.script[line_num] += '@???'
                i += 2
                continue
            # Variable name from vars table
            if b == 0xE7:
                #TODO is this null terminated or 2 bytes?
                offset = int.from_bytes(buf[i+1:i+3], byteorder='little')
                self.script[line_num] += '$' + self.variables[offset].decode('utf-8')
                i += 3
                continue
            # object method -  Fetch method name from vars table
            if b == 0xE8:
                #TODO is this null terminated or 2 bytes?
                offset = int.from_bytes(buf[i+1:i+3], byteorder='little')
                self.script[line_num] += '.' + self.variables[offset].decode('utf-8')
                i += 3
                continue
            # Function? name from var table
            if b == 0xE9:
                #TODO is this null terminated or 2 bytes?
                offset = int.from_bytes(buf[i+1:i+3], byteorder='little')
                self.script[line_num] += self.variables[offset].decode('utf-8')
                i += 3
                continue
            # Keyword
            if b == 0xEA:
                if n in functions:
                    self.script[line_num] += functions[n]
                else:
                    print(f'Unrecognized keyword 0x{n:02X}')
                    self.script[line_num] += '???'
                i += 2
                continue
            # Single char literal + null
            if b == 0xEF:
                self.script[line_num] += chr(n) 
                i += 3
                continue

            # check operators/symbols
            if b in operators:
                self.script[line_num] += f'{operators[b]}'
                i += 1
                continue

            # End Script
            if b == 0xF1:
                return 
            print(f'Failed to parse token {b:02X} in {hexlify(buf[i-2:i+3])}')
            return
            
for arg in sys.argv[1:]:
    kix = Kixtart(arg)
    kix.decrypt()
    #print(hexlify(kix.tokenized))
    print()
    for line in kix.script:
        if line:
            print(line)
    
