#!/usr/bin/env python3.7
import os

BLOCK_SIZE = 256

P = [
    (0, [1, 7]),
    (1, [0, 8]),
    (0, [5, 3]),
    (1, [8, 6]),
    (0, [3, 9]),
    (1, [4, 0]),
    (0, [9, 1]),
    (1, [6, 2]),
    (0, [7, 5]),
    (1, [2, 4]),
]

def n2B(b,length=BLOCK_SIZE):
    return list(map(int, bin(b)[2:].rjust(BLOCK_SIZE, '0')))

def B2n(b):
    return int("".join(map(str, b)), 2)

def swap(b):
    l = BLOCK_SIZE // 2
    mask = (1 << l) - 1
    return (b >> l) | ((b & mask) << l)

def bitchain(cb, state=0):
    if len(cb) == 0: 
        return cb
    b, ns = P[state]
    b0, bn = cb[0],cb[1:]
    return [b0 ^ b] + bitchain(bn, state=ns[b0])

def blockcipher(b):
    return B2n(bitchain(n2B(b)))

class CbC:

    def __init__(self, k, rounds):
        self.key = [k]
        self.rounds = rounds
        for i in range(1, self.rounds):
            k = swap(blockcipher(k))
            self.key.append(k)

    def encrypt(self, b):
        for i in range(self.rounds):
            b ^= self.key[i]
            b = blockcipher(b)
            b = swap(b)
        return b

if __name__ == "__main__":
    flag = bytes.hex(os.urandom(BLOCK_SIZE // 8))
    key = int(flag, 16)
    C = CbC(key, 99)
    print("Flag : AIS3{%s}" % flag)
    with open("data", "w") as f:
        for i in range(100):
            pt = int(bytes.hex(os.urandom(BLOCK_SIZE // 8)), 16)
            ct = C.encrypt(pt)
            f.write(str((pt, ct)) + "\n")
    
