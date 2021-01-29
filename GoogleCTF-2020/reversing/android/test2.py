#!/usr/bin/env python3
from pwnlib.util.iters import *
import string

g_class = [0x271986b,
           0xa64239c9,
           0x271ded4b,
           0x1186143,
           0xc0fa229f,
           0x690e10bf,
           0x28dca257,
           0x16c699d1,
           0x55a56ffd,
           0x7eb870a1,
           0xc5c9799f,
           0x2f838e65]

def R_func(a, b):
    if a == 0:
        return [0, 1]
    r = R_func(b % a, a)
    return [r[1] - b // a * r[0], r[0]]

g_int = 4

def breakme(flagString):
    g_arr  = ord(flagString[3]) << 0x18
    g_arr |= ord(flagString[2]) << 0x10
    g_arr |= ord(flagString[1]) << 0x8
    g_arr |= ord(flagString[0])

    m = 0x100000000
    g = R_func(g_arr, m)
    inv = (((g[0] % m) + m) % m)

    if inv == g_class[g_int]:
        return True
    else:
        return False

# CTF{y0u_c4n_k3ep_y0u
with open('log', 'w') as f:
    while g_int < 0xc:
        result = mbruteforce(breakme, string.printable, method='fixed', length=4, threads=8)
        print(result)
        f.write(result)
        g_int += 1