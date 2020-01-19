import random
import hashlib


def int2bits(x, nbits):
    x = bin(x)[2:].rjust(nbits, '0')
    assert len(x) == nbits
    return x


class SPN(object):
    def __init__(self, sbits, nblock, nround):
        self.sbits = sbits
        self.nblock = nblock
        self.nround = nround
        self.nbits = self.sbits * self.nblock

    def random_gen(self):
        sbox = list(range(1 << self.sbits))
        pbox = list(range(self.nbits))
        random.shuffle(sbox)
        random.shuffle(pbox)
        sbox = {
            int2bits(i, self.sbits): int2bits(e, self.sbits)
            for i, e in enumerate(sbox)}
        self.set_boxes(sbox, pbox)

    def set_boxes(self, sbox, pbox):
        self.sbox = sbox
        self.pbox = pbox

    def set_key(self, key):
        keys = [key]
        for _ in range(self.nround):
            key = hashlib.sha256(key).digest()
            key = int.from_bytes(key, 'little')
            key = int(int2bits(key, 256)[:self.nbits], 2)
            key = key.to_bytes((self.nbits + 7) // 8, 'little')
            keys.append(key)
        self.set_raw_keys(keys)

    def set_raw_keys(self, keys):
        assert len(keys) == self.nround + 1
        self.raw_keys = keys
        self.keys = [int.from_bytes(k, "little") for k in keys]
        self.keys = [int2bits(k, self.nbits) for k in self.keys]

    def add_round_key(self, x, k):
        return int2bits(int(x, 2) ^ int(k, 2), self.nbits)

    def substitute(self, x, sbox):
        return ''.join(
            sbox[x[block: block+self.sbits]]
            for block in range(0, self.nbits, self.sbits))

    def permute(self, x, pbox):
        return ''.join(x[i] for i in pbox)

    def run(self, x, sbox, pbox, keys):
        x = int2bits(int.from_bytes(x, "little"), self.nbits)
        y = 0
        for round, k in enumerate(keys[:-1]):
            x = self.add_round_key(x, k)
            x = self.substitute(x, sbox)
            y += sum(map(int, x))
            if round != self.nround - 1:
                x = self.permute(x, pbox)
        x = self.add_round_key(x, keys[-1])
        return y

    def encrypt(self, x):
        return self.run(x, self.sbox, self.pbox, self.keys)
