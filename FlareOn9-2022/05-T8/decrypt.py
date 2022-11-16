#!/usr/bin/env python3
import hashlib
import base64
import struct

def wstring(string):
    result = []
    for i in string:
        result += [i]
        result += [0]
    return bytes(result)

def context_create():
    context = dict()
    context['buf'] = [0 for i in range(256)]
    context['a'] = 0
    context['b'] = 0
    context['c'] = 0
    return context

def context_init(context, seed):
    context['a'] = len(seed)
    context['b'] = 0
    context['c'] = 0

    for i in range(256):
        context['buf'][i] = i

    g = 0

    for i in range(256):
        key1 = context['buf'][i]
        g = (g + seed[i % context['a']] + key1) % 256
        temp = context['buf'][g]
        context['buf'][i] = temp
        context['buf'][g] = key1

    return context

def context_encrypt(context, msgin):
    length = len(msgin)
    msgout = [0 for i in range(length)]

    for i in range(length):
        context['b'] = (context['b'] + 1) % 256
        context['c'] = (context['c'] + context['buf'][context['b']]) % 256
        temp = context['buf'][context['b']]
        context['buf'][context['b']] = context['buf'][context['c']]
        context['buf'][context['c']] = temp
        msgout[i] = msgin[i] ^ context['buf'][(context['buf'][context['b']] + context['buf'][context['c']]) & 0xff]
        
    return context, bytes(msgout)

def context_dump(context):
    for i in range(256):
        if i % 8 == 0:
            print()
        print(hex(context['buf'][i]), end=' ')
    print()
    print(context['a'])
    print(context['b'])
    print(context['c'])

def decrypt_part1(subarr):
    key1 = subarr[0]
    key2 = subarr[1]

    if subarr[1] <= 2:
        key1 -= 1
    if subarr[1] <= 2:
        key2 += 12

    key3 = ((key1 / 400 
             + subarr[3] + ((key1 + 4716) * 365.25) - ((key2 + 1) * -30.6001) - key1 / 100 + 2) - 1524.5 - 2451549.5) / 29.53
    key4 = key3 // 1
    val = round((key3 - key4) * 29.53)
    return val

word_table = [
    0x20, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x00, 0x30, 0x5F, 0x33, 0x00,
    0x2C, 0x00, 0x77, 0x7D, 0x70, 0x63, 0x74, 0x3C,
    0x7E, 0x7F, 0x3F, 0x72, 0x7E, 0x7C, 0x00, 0x00,
]

def decrypt_part2(val):
    if val > 26:
        return word_table[1+val]
    else:
        return word_table[val]

def decrypt_msg(arr):
    result = b''
    for subarr in arr:
        val = decrypt_part1(subarr)
        # print(val)
        word = decrypt_part2(val-1)
        print(chr(word))
        result += bytes([word])
        # break
    return result

####

# magic = wstring(b'FO913112')
magic = wstring(b'FO911950')
md5magic = hashlib.md5(magic).digest().hex().encode()
wmd5magic = wstring(md5magic)

context = context_create()
context = context_init(context, wmd5magic)
context_dump(context)

msgin = b'a\0h\0o\0y\0'

context, msgout = context_encrypt(context, msgin)
context_dump(context)

msgoute64 = base64.b64encode(msgout)
print(md5magic)
print(msgoute64)

#### 

data1 = bytes.fromhex('54645164425261316e784755303664624232374537535137544a322b6364377a73744c585251634c626d68326e5476446d3170354966542f4375304a7853686b3674485142525777506c6f397a413164495366736c6b4c674744733431574b313269625749666c714c45345971334f5949456e4c4e6a775648726a4c3255344c75336d732b485163346e664d57585067634f48623466686f6b6b39332f414a643547547543357a2b3459736d675268315a393079696e4c424b422b666d47557961675436676f6e2f4b486d4a6476414f51386e416e6c384b2f3058472b387a5951625a5277675936744876767066796e394f584379756374352f634f69384b5767414c7656485157616672703871422f4a74542b74357a6d6e657a516c70337a504c34736a32434a666355544b35636f70625a43794865785644346a4a4e2b4c657a4a45747244585031444a4e673d3d')
data1d64 = base64.b64decode(data1)

decrypt_context = context_create()
decrypt_context = context_init(decrypt_context, wmd5magic)

decrypt_context, data1dec = context_encrypt(decrypt_context, data1d64)
print(data1dec)
print(data1dec.hex())

wdata1 = []

for i in range(0, len(data1dec), 2):
    wdata1.append(struct.unpack('<H', data1dec[i:i+2])[0])

print(wdata1)

size = len(wdata1)
idx_list = [idx + 1 for idx, val in
            enumerate(wdata1) if val == ord(',')]

split_wdata1 = [wdata1[i: j] for i, j in
        zip([0] + idx_list, idx_list + 
        ([size] if idx_list[-1] != size else []))]

print(split_wdata1)
decode_msg = decrypt_msg(split_wdata1)
print(decode_msg)

####

# target = bytes.fromhex('56594255705a6447')
# target = base64.b64decode(target)
# 
# print(target)
# 
# for i in range(1, 2):
#     magicstr = f'FO9{i}'
#     print(magicstr)
#     magic = wstring(magicstr.encode())
#     md5magic = hashlib.md5(magic).digest().hex().encode()
#     wmd5magic = wstring(md5magic)
# 
#     context2 = context_create()
#     context2 = context_init(context2, wmd5magic)
# 
#     msgin = b's\0c\0e\0'
# 
#     context2, msgout = context_encrypt(context2, msgin)
# 
#     if target == msgout:
#         print('found: ' + i)
#         break
# 
# print('done')
