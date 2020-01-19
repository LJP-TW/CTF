#!/usr/bin/env python3
from Crypto.Util.number import *

with open('flag', 'rb') as f:
    flag = f.read()

# I think this is fast and fantastic, isn't it?
def fantasticPrime(l):
    fantastic = 18
    while True:
        p = 2
        while size(p) < l - fantastic:
            p *= getPrime(fantastic)
        for _ in range(2 ** fantastic):
            pp = p * getPrime(fantastic) + 1
            if isPrime(pp):
                return pp

def genkeys():
    e = 65537
    while True:
        p, q = fantasticPrime(512), fantasticPrime(512)
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
    print('m = {m % 2}')

def main():
    pub, pri = genkeys()
    while True:
        menu()
        cmd = input('> ')
        if cmd == '1':
            info(pub)
        elif cmd == '2':
            decrypt(pri)
        else:
            exit()

main()

