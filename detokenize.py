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
        while True:
            # parse line number
            if self.tokenized[i] == 0xEC:
                #denotes a signed short line number
                line_num = self.tokenized[i+1]
                try:
                    self.script[line_num] += ':' + self.labels[i] + '\n'
                except:
                    # No label for this line
                    pass
                    #print('No label for line {line_num}')
                i += 2
                continue
            if self.tokenized[i] == 0xED:
                #denotes a signed short line number
                line_num = int.from_bytes(self.tokenized[i+1:i+3], byteorder='little')
                try:
                    self.script[line_num] += ':' + self.labels[i] + '\n'
                except:
                    # No label for this line
                    pass
                    #print('No label for line {line_num}')
                i += 3
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
            if self.tokenized[i] == 0x07:
                # label, each time a label is encountered we just grab the next label from our array of them
                label = self.labels[label_count].decode('utf-8')
                label_count += 1
                self.script[line_num] += ':' + label 
                i += 1
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
                # Keyword
                if self.tokenized[i+1] in functions:
                    self.script[line_num] += functions[self.tokenized[i+1]]
                else:
                    print(f'Unrecognized keyword 0x{self.tokenized[i+1]:02X}')
                    self.script[line_num] += '???'
                i += 2
                continue
            if self.tokenized[i] == 0xEF:
                #single character + null
                self.script[line_num] += chr(self.tokenized[i+1]) 
                i += 3
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
    
