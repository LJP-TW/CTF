from struct import *

result = ''

with open('enc', 'rb') as f:
    for i in range(38):
        v4 = (i + 1) << (i + 2) % 0xa
        c = unpack('<i', f.read(4))
        v5 = (c[0] - 9011) // v4
        result += chr(v5)

print(result)

