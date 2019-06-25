import base64
from secret import register, taps

def toBin(s):
    ret = []
    if type(s) == type(b''):
        s = "".join(map(chr, s))
    for c in s:
        ret.append(bin(ord(c))[2:].zfill(8))
    return "".join(ret)

class LFSR:

    def __init__(self, register, taps):
        self.register = register
        self.taps = taps

    def next(self):
        ret = self.register[0]
        new = 0
        for i in self.taps:
            new ^= self.register[i]
        self.register.append(new)
        self.register = self.register[1:]
        return ret

with open('flag.png','rb') as f:
    flag = f.read()
    flag = base64.b64encode(flag)
    binary = toBin(flag)

lfsr = LFSR(register,taps)
enc = ''
for b in binary:
    enc += str(int(b) ^ lfsr.next())
    
with open('enc.png', 'w') as f:
    f.write(hex(int(enc,2))[2:])


