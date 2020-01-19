from sympy import *
import random

def op1(p, s):
    return sum([i * j for i, j in zip(s, p)]) % 256

random.seed('oalieno')
p = [int(random.random() * 256) for i in range(16)]
s = [int(random.random() * 256) for i in range(16)]
k = []

for i in range(16):
    k += [op1(p, s)]
    s = s[1:] + [k[-1]]

print(f'k = {k}')
