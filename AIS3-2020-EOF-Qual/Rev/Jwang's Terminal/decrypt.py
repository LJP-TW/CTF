#!/usr/bin/env python3
from Crypto.Cipher import AES  
import struct

def decrypt(content):
    iv  = b'\xA1\xA4\xC4\x1C\x1C\x5B\xC5\x2E\x90\xDA\xB8\xFE\x46\x23\xBF\xBB'
    key = b'\xE9\x31\xDF\xC0\xC3\x7A\xEE\xAC\x6E\xC9\x87\x1C\x8A\x7A\xF6\xEC'

    cipher = AES.new(key, AES.MODE_CBC, iv)

    return cipher.encrypt(content).decode(errors='ignore')

def u32(bs):
    return struct.unpack('<I', bs)[0]

def u16(bs):
    return struct.unpack('<H', bs)[0]

def parseFS(fs):
    idx = 0x10
    allplaintext = ''

    def parseItem(fs, idx):
        i_type = u32(fs[idx:idx+4])
        idx += 4
        i_namelen = u16(fs[idx:idx+2])
        idx += 2
        i_name = fs[idx:idx+i_namelen]
        idx += i_namelen
        i_contentlen = u32(fs[idx:idx+4])
        idx += 4
        i_content = fs[idx:idx+i_contentlen]
        idx += i_contentlen
        idx += 4
        return (i_type, i_name, i_content, idx)

    while True:
        item_type, item_name, item_content, idx_next = parseItem(fs, idx)
        idx = idx_next

        if item_name == b'README.txt':
            break

        if item_type == 1:
            print(item_type)
            print(item_name)
            print(item_content)
            plain_content = decrypt(item_content)
            allplaintext += plain_content
    
    return allplaintext

with open('hackerFS', 'rb') as f:
    fs = f.read()

allplaintext = parseFS(fs)

with open('output.txt', 'wb') as f:
    f.write(allplaintext.encode())


