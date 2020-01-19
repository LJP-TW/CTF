#!/bin/env python3

import gmpy2
import random
import hashlib


def gen():
    while True:
        p = [gmpy2.next_prime(random.randrange(1<<48)) for _ in range(50)]
        o = 2
        for pi in p:
            o *= pi
        n = o + 1
        if gmpy2.is_prime(n):
            g = 2
            if pow(g, o // 2, n) == n - 1:
                return g, n


def main():
    g, n = gen()
    k = random.randrange(n - 1)
    c = pow(g, k, n)

    with open('../flag.txt', 'rb') as f:
        flag = f.read()
    k = hashlib.sha512(str(k).encode('ascii')).digest()
    enc = bytes(ci ^ ki for ci, ki in zip(flag.ljust(len(k), b'\0'), k))

    print('g =', g)
    print('n =', n)
    print('c =', c)
    print('flag =', enc.hex())


if __name__ == '__main__':
    main()
