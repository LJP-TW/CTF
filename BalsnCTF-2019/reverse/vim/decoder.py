import codecs

padding = 'Welcome_to_th1s_'
flag = 'abcdefghijklmnop'
# flag = '|kjjhlhlxa_meste'
table2 = list(ord(c) % 32 + 1 for c in codecs.encode(padding + flag, 'rot_13'))
tableMixed = []
table36 = []

for i in range(4):
    for j in range(4):
        tableMixed.append(table2[i + j * 4])

temp = []
for base in range(4):
    for i, n in enumerate(tableMixed):
        num = 0
        n = n - 1
        for r in range(31):
            if n > 0:
                n = n - 1
                num = num + table2[base * 4 + i % 4] - 1
                num = num % 32
        temp.append(num + 1)
        if len(temp) == 4:
            print(temp)
            total = temp[0]
            for t in temp[1:]:
                total = total + t - 1
            total = total % 32
            table36.append(total)
            temp = []

print(table2)
print(tableMixed)
print(table36)
print('-----------')

tableMixed2 = []
for i in range(4):
    for j in range(4):
        tableMixed2.append(table2[16 + i + j * 4])

table53 = []
temp = []
for base in range(4):
    for i, n in enumerate(tableMixed2):
        num = 0
        n = n - 1
        for r in range(31):
            if n > 0:
                n = n - 1
                num = num + table36[base * 4 + i % 4] - 1
                num = num % 32
        temp.append(num + 1)
        if len(temp) == 4:
            total = temp[0]
            for t in temp[1:]:
                total = total + t - 1
            total = total % 32
            table53.append(total)
            temp = []

print(table36)
print(tableMixed2)
print(table53)
print('-----------')

table70 = [1]
index = 0
for x, y in zip(table36, table53):
    _x = x
    if _x % 2 == 1:
        _x = _x + 1 
    _x /= 2
    if _x % 2 == 1:
        _x = _x + 1
    _x /= 2
    x = x * 2 - 2
    x = x % 32 + 1
    x = x * 2 - 2
    x = x % 32 + 1
    x = x * 2 - 2
    x = x % 32 + 1
    x = x + _x - 2
    x = x % 32 + 1

    _y = y
    if _y % 2 == 1:
        _y = _y + 1
    _y /= 2
    if _y % 2 == 1:
        _y = _y + 1
    _y /= 2
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

table70 = table70[1:]
table87 = table70

answer = [24, 31, 18, 22, 27, 8, 23, 4, 2, 19, 5, 18, 3, 11, 22, 10]
print(answer)
print(table87)

for a, r in zip(answer, table87):
    if a != r:
        print('Wrong!')
        exit()
print('Correct!')
print('Balsn{%sr}' % flag)
