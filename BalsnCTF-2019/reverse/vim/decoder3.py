import codecs
import numpy as np

padding = 'Welcome_to_th1s_'
# flag = 'abcdefghijklmnop'
flag = '|kjjhlhlxa_meste'
table2 = list(ord(c) % 32 + 1 for c in codecs.encode(padding + flag, 'rot_13'))

def toBlock(blk):
    ret = []
    for i in range(4):
        for j in range(4):
            ret.append(blk[i + j * 4])
    return ret

def func1(P, Q):
    P = np.array(P).reshape((4, 4))
    Q = np.array(Q).reshape((4, 4)).transpose()
    P = P - 1
    Q = Q - 1
    print(P)
    print(Q)

    ret = []
    # P * Q
    for i in range(4):
        for j in range(4):
            num = 0
            for k in range(4):
                num += (P.item((i, k)) * Q.item((k, j)))
            ret.append((num + 1) % 32)
    
    ret = np.array(ret).reshape((4, 4)).transpose().flatten().tolist()
    print(ret)
    return ret

def func2(X, Y):
    table70 = [1]
    index = 0
    for x, y in zip(X, Y):
        _x = x
        if _x % 2 == 1:
            _x = _x + 1 
        _x //= 2 # _x >> 2
        if _x % 2 == 1:
            _x = _x + 1
        _x //= 2
        # _x = x >> 4
        x = x * 2 - 2 # x <<= 1
        x = x % 32 + 1 # x 
        x = x * 2 - 2
        x = x % 32 + 1
        x = x * 2 - 2
        x = x % 32 + 1
        x = x + _x - 2
        x = x % 32 + 1

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

        v = (table70[index] + y - 2) % 32 + 1
        v = (v + x - 2) % 32 + 1
        table70.append(v)
        index += 1
        
    return table70[1:]

X = func1(toBlock(table2[:16]), table2[:16])
Y = func1(toBlock(table2[16:32]), X)
my_ans = func2(X,Y)

print(my_ans)
answer = [24, 31, 18, 22, 27, 8, 23, 4, 2, 19, 5, 18, 3, 11, 22, 10]
print(my_ans == answer)
