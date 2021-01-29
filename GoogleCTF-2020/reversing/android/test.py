#!/usr/bin/env python3
from math import *
from ctypes import *

def R_func(a, b):
    if a == 0:
        return [0, 1]
    r = R_func(b % a, a)
    print(r)
    return [r[1] - b // a * r[0], r[0]]
    

a = 17
b = 25
print(a)
print(b)
g = R_func(a, b)
print(gcd(a, b))
print(g)
print([g[0] + b // a * g[1], g[1]])

