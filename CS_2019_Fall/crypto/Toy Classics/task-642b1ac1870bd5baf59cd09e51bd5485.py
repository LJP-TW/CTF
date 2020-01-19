#!/bin/env python3

import string
import random
import hashlib


def main():
    with open('plain.txt') as f:
        plain = f.read().strip()

    charset = string.ascii_lowercase + string.digits + ',. '
    charset_idmap = {e: i for i, e in enumerate(charset)}
    assert all(c in charset for c in plain)

    ksz = 80
    plain = [charset_idmap[c] for c in plain]
    key = [random.randrange(len(charset)) for _ in range(ksz)]

    def encrypt(plain, key):
        N, ksz = len(charset), len(key)
        return ''.join(charset[(c + key[i % ksz]) % N] for i, c in enumerate(plain))

    print('y =', encrypt(plain, key))


    with open('flag.txt', 'rb') as f:
        flag = f.read()
    k = hashlib.sha512(''.join(charset[k] for k in key).encode('ascii')).digest()
    enc = bytes(ci ^ ki for ci, ki in zip(flag.ljust(len(k), b'\0'), k))
    print('enc =', enc.hex())


if __name__ == '__main__':
    main()
