#!/usr/bin/env python3

from sympy import *
from re import *

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
    cmds = []
    flag = ''
    table = [251, 241, 239, 233, 229, 227, 223, 211][::-1]

    for i, c in enumerate(code):
        if i >= 94 and i <= 238 and i % 4 == 2:
            cmds.append('{0}'.format(factorint(c[0])))

    for strcmd in cmds:
        n = 1
        result = 0
        print('now cmd: {0}'.format(strcmd))
        for t in table:
            if search(str(t), str(strcmd)) != None:
                result += n
            n *= 2
        flag += chr(result)
    
    print(flag)
    

if __name__ == "__main__":
    main()
