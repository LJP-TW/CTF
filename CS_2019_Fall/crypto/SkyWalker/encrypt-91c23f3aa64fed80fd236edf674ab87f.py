#!/usr/bin/env python3
from Crypto.Util.number import *

def genkeys():
    e = 3
    while True:
        p, q = getPrime(512), getPrime(512)
        n, phi = p * q, (p - 1) * (q - 1)
        if GCD(e, phi) == 1:
            d = inverse(e, phi)
            return n, e, d

def pad(x: bytes):
    if len(x) > 128 - 2:
        raise ValueError("message too big")
    return b'\x00' + b'\x87' * (128 - 2 - len(x)) + b'\x01' + x

def main():
    n, e, _ = genkeys()

    with open('./flag', 'rb') as f:
        flag = f.read()

    m = bytes_to_long(pad(flag))
    c = pow(m, e, n)

    print(f'n = {n}')
    print(f'c = {c}')

main()
