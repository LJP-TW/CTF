#!/usr/bin/env python3

import sys
from sympy import *

def convert_frac(frac):
    s = frac.split('/')
    p = True
    if isprime(int(s[0])) == False or isprime(int(s[1])) == False:
        p = False
    return [int(s[0]), int(s[1]), p]

def convert_code(code):
    return [convert_frac(f) for f in code.split()]

def convert_primes(primes):
    return [int(x) for x in primes.split()]

def read_and_convert(filename):
    with open(filename, 'r') as f:
        primes = f.readline().strip()
        out = f.readline().strip()
        state = f.readline().strip()
        code = f.readline().strip()
        return convert_primes(primes), int(out), int(state), convert_code(code)


def main():
    primes, out, state, code = read_and_convert('flag.ftb')

    for i in primes:
        if isprime(i) == False:
            print('Not prime !')
            return

    for i, c in enumerate(code):
        a = factorint(c[0])
        if a == {}:
            a = {1}
        b = factorint(c[1])
        if b == {}:
            b = {1}
        newcode = [a, b]
        print('{0}: {1}'.format(i, newcode))

if __name__ == "__main__":
    main()
