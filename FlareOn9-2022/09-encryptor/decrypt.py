#!/usr/bin/env python3

with open('09_encryptor/SuspiciousFile.txt.Encrypted', 'rb') as f:
    content = f.read().split(b'\n')[:-1]
    outputNum = int(content[-1][-0x100:], 16)
    Key3_A0_409060 = int(content[-2][-0x100:], 16)
    Key2_n_88_409100 = int(content[-3][-0x100:], 16)
    Key1_20_4050A0 = int(content[-4][-0x100:], 16)
    
i = 0
for line in content:
    print('{}: {}\n'.format(i, line))
    i += 1
    
print('{}: {}\n'.format('Key1_20_4050A0  ', hex(Key1_20_4050A0)))
print('{}: {}\n'.format('Key2_n_88_409100', hex(Key2_n_88_409100)))
print('{}: {}\n'.format('Key3_A0_409060  ', hex(Key3_A0_409060)))
print('{}: {}\n'.format('outputNum       ', hex(outputNum)))

def dump(num):
    s = hex(num)[2:].rjust(0x10 * 0x12, '0')
    s = [s[i:i+0x10] for i in range(0, len(s), 0x10)][::-1]
    for i in range(0, len(s), 2):
        print('{} {}'.format(s[i], s[i+1]))
    



e = 0x10001

num0 = pow(outputNum, e, Key2_n_88_409100)

dump(num0)

