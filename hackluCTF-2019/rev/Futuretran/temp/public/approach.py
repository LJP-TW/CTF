#!/usr/bin/env python3

import sys
from sympy import *

no_debug_id = [91]

def run(state, code):
    size = len(code)
    idx = 0
    while idx < size:
        cur_ins = code[idx]
        idx += 1
        tmp = state * cur_ins[0]
        if tmp % cur_ins[1] == 0:
            state = tmp // cur_ins[1]
            if idx - 1 not in no_debug_id:
                print('change state: at id {0}'.format(idx - 1))
                print(' from : {0}'.format(factorint(tmp)))
                print(' to   : {0}'.format(factorint(state)))
            idx = 0

    return state

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
    primes, out, state, code = read_and_convert('temp.ftb')
    flag = 'flag{akisjwismxjsiwopslwksoaawoxowrp}'

    for (c, p) in zip(flag, primes):
        state *= p ** ord(c)

    state = run(state, code)

    print('result: {0}'.format(factorint(state)))

if __name__ == "__main__":
    main()
