#!/usr/bin/env python3

def context_init(seed):
    a = 0
    b = 0
    table = [0 for i in range(256)]

    for i in range(256):
        table[i] = i
    
    idx = 0
    key2 = 0
    for i in range(256):
        key1 = table[i]
        key2 = (key1 + key2 + seed[idx]) & 0xff
        table[i] = table[key2]
        table[key2] = key1
        idx = (idx + 1) % len(seed)

    return a, b, table

def context_encrypt(a, b, table, datain):
    dataout = [0 for _ in range(len(datain))]
    for i in range(len(datain)):
        a = (a + 1) & 0xff
        key1 = table[a]
        b = (b + key1) & 0xff
        key2 = table[b]
        table[a] = key2
        table[b] = key1
        dataout[i] = datain[i] ^ table[(key1 + key2) & 0xff]

    return a, b, table, bytes(dataout)

seed = b'\x55\x8B\xEC\x83\xEC\x20\xEB\xFE'

a, b, table = context_init(seed)

data_enc1 = b'\x3E\x39\x51\xFB\xA2\x11\xF7\xB9\x2C'

a, b, table, data_dec1 = context_encrypt(a, b, table, data_enc1)

print(data_dec1)

data_enc2 = b'\xE1\x60\xA1\x18\x93\x2E\x96\xAD\x73\xBB\x4A\x92\xDE\x18\x0A\xAA\x41\x74\xAD\xC0\x1D\x9F\x3F\x19\xFF\x2B\x02\xDB\xD1\xCD\x1A'

a, b, table, data_dec2 = context_encrypt(a, b, table, data_enc2)

print(data_dec2)