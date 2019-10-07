
# coding: utf-8

# In[6]:


from sympy import Matrix, pprint
import codecs
from collections import defaultdict
import numpy as np

def func1(lst, lng):
    def toBlock(blk):
        ret = []
        for i in range(4):
            for j in range(4):
                ret.append(blk[i + j * 4])
        return ret
    
    lst = toBlock(lst)
    ret = []
    temp = []
    for base in range(4):
        for i, n in enumerate(lst):
            num = 0
            n = n - 1
            for r in range(31):
                if n > 0:
                    n = n - 1
                    num = num + lng[base * 4 + i % 4] - 1
                    num = num % 32
            temp.append(num + 1)
            if len(temp) == 4:
                total = temp[0]
                for t in temp[1:]:
                    total = total + t - 1
                total = total % 32
                ret.append(total)
                temp = []
    return ret


def solveP(fun1_res, Q):
    m = 32
    fun1_res = np.array(fun1_res).reshape((4, 4))
    Q = np.array(Q).reshape((4, 4))
    PT = np.matmul( Matrix(Q - 1).inv_mod(32) , fun1_res - 1) % m
    P = (PT + 1) % m
    return list(P.reshape(16))

def shift(y):
    _y = y
    if _y % 2 == 1:
        _y = _y + 1
    _y //= 2
    if _y % 2 == 1:
        _y = _y + 1
    _y //= 2
    y = y * 2 - 2
    y = y % 32 + 1
    y = y * 2 - 2
    y = y % 32 + 1
    y = y * 2 - 2
    y = y % 32 + 1
    y = y + _y - 2
    y = y % 32 + 1
    return y

shiftMap = {0:0}
revShiftMap = {0:0}

for i in range(32):
    the = shift(i)
    shiftMap[i] = the
    revShiftMap[the] = i

    
def func2(X, Y):
    table70 = [1]
    index = 0
    for x, y in zip(X, Y):

        v = (table70[index] +shiftMap[y] - 2) % 32 + 1
        v = (v + shiftMap[x] - 2) % 32 + 1
        table70.append(v)
        index += 1
        
    return table70[1:]

def solveY(X, V):
    prev = 1
    Y = []
    for x, v in zip(X, V):
        the_v = v
        v = ( (v - 1) % 32 - shiftMap[x] + 2) % 32
        yp = ( (v - 1) % 32 - prev + 2) % 32 
        prev = the_v
        
        Y.append(revShiftMap[yp])
        
    return Y


ans_dict = defaultdict(list)
for i in range(128):
    ans_dict[ord((codecs.encode(chr(i), 'rot_13')[0])) % 32 + 1].append(chr(i))
ans_dict[0] = ['_','_','_','_']


# In[13]:



padding = 'Welcome_to_th1s_'
flag = 'qristuvwxezabcde'

table2 = list(ord(c) % 32 + 1 for c in codecs.encode(padding + flag, 'rot_13'))

print("trying solveP")
print("original answer:", table2[:16])
print("solved answer:",solveP(func1(table2[:16], table2[:16]), table2[:16]))

X = func1(table2[:16], table2[:16])
Y = func1(table2[16:32],X)
my_ans = func2(X,Y)

print("trying solveY")
print("original answer:", Y)
print("solved answer:", solveY(X, my_ans))

print("trying reversing my_ans")

solved_Y = solveY(X, my_ans)
P = solveP(solved_Y, X)
print("original answer:", table2[16:32])
print("solved answer:",P)
for i in P:
    print(ans_dict[i][3], end="")
print()


# In[14]:



answer = [23, 30, 17, 21, 26, 7, 22, 3, 1, 18, 4, 17, 2, 10, 21, 9]
answer =  [24, 31, 18, 22, 27, 8, 23, 4, 2, 19, 5, 18, 3, 11, 22, 10]
print("trying reversing answer")
solved_Y = solveY(X, answer)
print(solved_Y)
P = solveP(solved_Y, X)
print(P)
s = ""
for i in P:
    s += (ans_dict[i][3])
    
    
print(f"Balsn{{{s}r}}")

