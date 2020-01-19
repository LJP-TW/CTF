#!/usr/bin/env python3
from Crypto.Util.number import *

with open('flag', 'rb') as f:
    flag = f.read()

def genkeys():
    e = 65537
    while True:
        p, q = getPrime(512), getPrime(512)
        n, phi = p * q, (p - 1) * (q - 1)
        if GCD(e, phi) == 1:
            d = inverse(e, phi)
            return (n, e), (n, d)

def menu():
    print(f'{" menu ":=^20}')
    print('1) info')
    print('2) decrypt')

def info(pub):
    n, e = pub
    m = bytes_to_long(flag)
    c = pow(m, e, n)
    print(f'c = {c}')
    print(f'e = {e}')
    print(f'n = {n}')

def decrypt(pri):
    n, d = pri
    c = int(input())
    m = pow(c, d, n)
    print(f'm = {m % (2 ** 4)}')

def main():
    pub, pri = genkeys()
    for _ in range(1024 // 4 + 5):
        menu()
        cmd = input('> ')
        if cmd == '1':
            info(pub)
        elif cmd == '2':
            decrypt(pri)
        else:
            exit()

main()

