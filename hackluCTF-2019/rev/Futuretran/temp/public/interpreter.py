#!/usr/bin/env python3

import sys

def run(state, code):
    size = len(code)
    idx = 0
    while idx < size:
        cur_ins = code[idx]
        idx += 1
        tmp = state * cur_ins[0]
        if tmp % cur_ins[1] == 0:
            state = tmp // cur_ins[1]
            idx = 0

    return state

def convert_frac(frac):
    s = frac.split('/')
    return [int(s[0]), int(s[1])]

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
    if len(sys.argv) < 3:
        print(f'usage: {sys.argv[0]} <code> <flag>')
        sys.exit(1)

    primes, out, state, code = read_and_convert(sys.argv[1])
    flag = sys.argv[2]

    for (c, p) in zip(flag, primes):
        state *= p ** ord(c)

    state = run(state, code)

    if state % out:
        print('correct :)')
    else:
        print('wrong :(')

if __name__ == "__main__":
    main()