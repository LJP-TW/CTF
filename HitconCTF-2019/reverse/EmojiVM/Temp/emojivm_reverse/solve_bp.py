m2 = [24, 5, 29, 16, 66, 9, 74, 36, 0, 91, 8, 87, 0, 114, 48, 9, 108, 86, 64, 9, 91, 5, 26, 0, 0]
m4 = [142, 99, 205, 18, 75, 88, 21, 23, 81, 34, 217, 4, 81, 44, 25, 21, 134, 44, 209, 76, 132, 46, 32, 6, 0]
m5 = [0 for i in range(5)]
m1 = list('hitcon{someasdfghjiklmn}\x00') # max len: 30
go = 0
stack = []

# 6814
while True:
    if ord(m1[m5[1]]) == 0:
        go = 7052
        break
    if ord(m1[m5[1]]) == 10:
        go = 6997
        break
    
    m5[0] += 1 # len(m1)
    m5[1] += 1

if go <= 6997:
    m1[m5[1]] = 0
    
# 7052
if m5[0] != 24: # Flag length 24
    print('gg')
    exit()

# 7111
m5[1] = 0

# 7118
while True:
    c = False
    d = False
    if (m5[1] + 1) % 5 == 0:
        # goto 7294
        d = True

    # 7177
    while True:
        if d == False:
            c = False
            m5[1] += 1
            if m5[1] < 24:
                # goto 7118
                c = True
            break
        else:
            # 7294
            if m1[m5[1]] != 45:
                print('gg')
                exit()
            
            # 7356
            # goto 7177
    
    if c == True:
        continue
    else:
        # 7249
        # goto 7401
        break
        
# 7401
m5[1] = 0
while True:
    m5[2] = m5[1] % 4
    if m5[2] == 0:
        # 7750
        m3[m5[1]] = (m1[m5[1]] + 30)
        # goto 7633
    # 7474
    elif m5[2] == 1:
        # 7820
        m3[m5[1]] = (m1[m5[1]] - 8) ^ 7
        # goto 7633
    # 7527
    elif m5[2] == 2:
        # 7887
        m3[m5[1]] = ((m1[m5[1]] + 44) ^ 68) - 4
        # goto 7633
    # 7580
    elif m5[3] == 3:
        # 7969
        m3[m5[1]] = (m1[m5[1]] ^ 101) ^ (172 & 20)
        # goto 7633
        
    # 7633
    m5[1] += 1
    if m5[1] < 24:
        # goto 7408
        continue
    
    # 7705
    break

# 8075
m5[1] = 0
m5[2] = 0
while True:
    c = False
    d = False
    if m4[m5[1]] == m3[m5[1]]:
        # goto 8284
        d = True
    
    # 8151
    if d == False:
        m5[2] -= 1
    while True:
        if d == False:
            m5[1] += 1
            c = False
            if m5[1] < 24:
                c = True
            break
        else:
            # 8284
            m5[2] += 1
            d = False
            continue
        
    if c == True:
        continue
    else:
        break
    
# 8342
if m5[2] != 24:
    print('gg')
    exit()
    
# 8401
m5[1] = 0
while True:
    m2[m5[1]] = m1[m5[1]] ^ m2[m5[1]]
    m5[1] += 1
    if m5[1] >= 24:
        break

# 8505
# goto 8700
print(m2)











