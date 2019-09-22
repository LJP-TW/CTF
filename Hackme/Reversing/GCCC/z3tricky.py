from z3 import *

a = BitVec('a', 32)
b = BitVec('b', 32)
c = BitVec('c', 33)
d = BitVec('d', 33)

# Test 1 ##################

s = Solver()
s.add(a == 0x80000000)
s.add(b == a >> 1)

s.check()
m = s.model()
A = m[a].as_long()
B = m[b].as_long()
print(hex(A))
print(hex(B))
print('')

# Test 2 ##################

s = Solver()
s.add(c == 0x80000000)
s.add(d == c >> 1)

s.check()
m = s.model()
C = m[c].as_long()
D = m[d].as_long()
print(hex(C))
print(hex(D))
print('')

# Test 3 ##################

e = 0x80000000
f = e >> 1
print(hex(e))
print(hex(f))
