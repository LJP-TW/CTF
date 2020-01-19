#!/bin/env python3

import os
import hashlib
from spn_side import SPN


def main():
    key = os.urandom(8)

    cipher = SPN(sbits=4, nblock=16, nround=4)
    cipher.random_gen()
    cipher.set_key(key)

    print('sbox =', cipher.sbox)
    print('pbox =', cipher.pbox)


    for _ in range(10000):
        x = os.urandom(8)
        y = cipher.encrypt(x)
        print('x =', x.hex())
        print('y =', y)


    with open('../flag.txt', 'rb') as f:
        flag = f.read()
    k = hashlib.sha512(key).digest()
    enc = bytes(ci ^ ki for ci, ki in zip(flag.ljust(len(k), b'\0'), k))
    print('enc =', enc.hex())


if __name__ == '__main__':
    main()
