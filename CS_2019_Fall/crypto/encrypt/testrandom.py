from sympy import *
import random

random.seed('oalieno')
k = [int(random.random() * 256) for i in range(16)]
p = [i for i in range(16)]
random.shuffle(p)
s = [i for i in range(256)]
random.shuffle(s)

print(f'k = {k}')
print(f'p = {p}')
print(f's = {s}')
