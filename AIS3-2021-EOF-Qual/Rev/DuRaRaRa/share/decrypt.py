#!/usr/bin/env python3
import itertools
import string
import hashlib

def animate(now, total):
    print('[', end='')
    percent = now * 100 // total
    star = percent * 30 // 100
    empty = 30 - star
    print('*' * star, end='')
    print('_' * empty, end='')
    print('] ', end='')
    print('%.4f' % (now / total), end='')
    print('%', end='\r')


def breakhash(target, length):
    m = hashlib.md5()
    characters = string.printable[:62] + ' {}'
    total = pow(len(characters), length)
    now = 0
    
    def pw_guess():
        res = itertools.product(characters, repeat=length)
        for guess in res:
            yield guess

    # Make generator object
    guess_generator = pw_guess()
    for guess in guess_generator:
        now += 1
        animate(now, total)

        gstr = ''
        for i in range(5):
            gstr += str(guess[i])

        m.update(gstr.encode())
        h = int(m.hexdigest(), 16)
        if h == target:
            print("Password acquired: " + str(gstr))
            return gstr
            
    return ''

xor_key = 0xA88121E46E48322B13328CEBF4FB6C1E

with open('./secret.txt') as f:
    dc = f.read()

partial_dc = []
for i in range(0, len(dc), 32):
    pdc = int(dc[i:i+32], 16) ^ xor_key
    partial_dc.append(pdc)
    print(hex(pdc))

FLAG = ''
for i in partial_dc:
    pf = breakhash(i, 5)
    FLAG += pf

print(FLAG)