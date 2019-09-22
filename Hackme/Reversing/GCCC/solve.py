from z3 import *

s = Solver()
result = [BitVec('result%d' % i, 33) for i in range(32)]
num = [BitVec('num%d' % i, 8) for i in range(32)]
str1 = [BitVec('str1_%d' % i, 8) for i in range(32)]
numArray = [BitVecVal(i, 8) for i in [164, 25, 4, 130, 126, 158, 91, 199, 173, 252, 239, 143, 150, 251, 126, 39, 104, 104, 146, 208, 249, 9, 219, 208, 101, 182, 62, 92, 6, 27, 5, 46]]

for i, c in enumerate(list('FLAG{')):
    s.add(str1[i] == ord(c))
s.add(str1[31] == ord('}'))

for i in range(5, 31):
    s.add(Or(And(str1[i] >= ord('A'), str1[i] <= ord('Z')), 
        str1[i] == ord(' ')))

s.add(num[0] == 0)
for i in range(31):
    s.add(str1[i] == numArray[i] ^ num[i] ^ Extract(7, 0, result[i]))
    s.add(num[i + 1] == num[i] ^ numArray[i])
    s.add(result[i + 1] == result[i] >> 1)
   
if s.check() == sat:
    m = s.model()
    r = m[result[0]].as_long()
    print('result     : %d' % r)
    print('result hex : %s' % hex(r))
    print('str1       : %s' % ''.join(chr(m[str1[i]].as_long()) for i in range(32)))
else:
    print('GG')
