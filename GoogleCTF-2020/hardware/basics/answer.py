#!/usr/bin/env python
from pwn import *

kittens = '00001010101011111110111101001011111000101101101111001100'

# magic = kittens[0:10] + kittens[30:42] +  kittens[10:30] + kittens[42:56]
magic = kittens[42:56] + kittens[10:30] + kittens[30:42] + kittens[0:10]
print(magic)

magic_list = [magic[idx:idx+7] for idx in range(0, len(magic), 7)]
print(magic_list)

input_list = []
# order = [0, 5, 2, 7, 4, 1, 6, 3]
order = [0, 1, 3, 6, 4, 7, 2, 5]
for i in order:
    input_list.append(magic_list[i])
print(input_list)

c_list = ''
for i in input_list:
    c = int('0b' + i, 2)
    c_list += chr(c)
    print(c)

# p = process('./obj_dir/Vcheck')
p = remote('basics.2020.ctfcompetition.com', 1337)
print(p.recvline())
p.sendline(c_list)
for i in range(10*9+1):
    print(p.recvline())
p.close()
