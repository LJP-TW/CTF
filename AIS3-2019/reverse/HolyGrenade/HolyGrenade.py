# Python bytecode 3.7 (3394)
# Embedded file name: HolyGrenade.py
# Size of source mod 2**32: 829 bytes
# Decompiled by https://python-decompiler.com
# from secret import flag
from hashlib import md5

flag = [41, 49, 53, 33]

def OO0o(arg):
    arg = bytearray(arg, 'ascii')
    for Oo0Ooo in range(0, len(arg), 4):
        O0O0OO0O0O0 = arg[Oo0Ooo]
        iiiii = arg[(Oo0Ooo + 1)]
        ooo0OO = arg[(Oo0Ooo + 2)]
        II1 = arg[(Oo0Ooo + 3)]
        arg[Oo0Ooo + 2] = II1
        arg[Oo0Ooo + 1] = O0O0OO0O0O0
        arg[Oo0Ooo + 3] = iiiii
        arg[Oo0Ooo] = ooo0OO

    return arg.decode('ascii')


flag += '0' * (len(flag) % 4)
for Oo0Ooo in range(0, len(flag), 4):
    print(OO0o(md5(bytes(flag[Oo0Ooo:Oo0Ooo + 4])).hexdigest()))
