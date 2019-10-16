m2 = [24, 5, 29, 16, 66, 9, 74, 36, 0, 91, 8, 23, 64, 0, 114, 48, 9, 108, 86, 64, 9, 91, 5, 26, 0, 0]
m3 = [0 for i in range(30)]
m4 = [142, 99, 205, 18, 75, 88, 21, 23, 81, 34, 217, 4, 81, 44, 25, 21, 134, 44, 209, 76, 132, 46, 32, 6]
m5 = [0 for i in range(5)]
# m1 = [ord(x) for x in list('hitc-n{so-masd-ghji-lmn}\x00')] # max len: 30
go = 0
stack = []

m1 = [0 for i in range(25)]
count = 0
for y in m4:
    f = count % 4
    if f == 0:
        m1[count] = y - 30
    elif f == 1:
        m1[count] = (y ^ 7) + 8
    elif f == 2:
        m1[count] = ((y + 4) ^ 68) - 44
    elif f == 3:
        m1[count] = y ^ 97
    
    count += 1

print(''.join(chr(i) for i in m1))

# 6814
while True:
    if m1[m5[1]] == 0:
        break
    if m1[m5[1]] == 10:
        m1[m5[1]] = 0
        break
    
    m5[0] += 1 # len(m1)
    m5[1] += 1
    
# 7052
# Flag length 24
if m5[0] != 24: 
    print('gg flag length')
    exit()

# 7111
m5[1] = 0

# 7118
while True:
    stay = False
    check = False
    if (m5[1] + 1) % 5 == 0:
        # goto 7294
        check = True

    # 7177
    while True:
        if check == False:
            stay = False
            m5[1] += 1
            if m5[1] < 24:
                # goto 7118
                stay = True
            break
        else:
            # 7294
            if m1[m5[1]] != 45:
                print('gg != 45')
                exit()
            check = False
            
            # 7356
            # goto 7177
    
    if stay == True:
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
    elif m5[2] == 3:
        # 7969
        m3[m5[1]] = (m1[m5[1]] ^ 97)
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
    gonext = False
    right = False
    if m4[m5[1]] == m3[m5[1]]:
        # goto 8284
        right = True
    
    # 8151
    if right == False:
        m5[2] -= 1
    while True:
        if right == False:
            m5[1] += 1
            gonext = False
            if m5[1] < 24:
                gonext = True
            break
        else:
            # 8284
            m5[2] += 1
            right = False
            continue
        
    if gonext == True:
        continue
    else:
        break
    
# 8342
if m5[2] != 24:
    print('gg m3 != m4')
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
print(''.join(chr(c) for c in m2))











