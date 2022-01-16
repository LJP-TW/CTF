#!/usr/bin/env python3

with open('./secret.bin', 'rb') as f:
    secret = list(f.read())

def animate(now, total):
    print('[', end='')
    percent = now * 100 // total
    star = percent * 30 // 100
    empty = 30 - star
    print('*' * star, end='')
    print('_' * empty, end='')
    print('] ', end='')
    print('%.4f' % (now * 100 / total), end='')
    print('%', end='\r')

for i in range(1, 144):
    output_f = './out_' + str(i) + '.jpg'
    filename = './' + str(i) + '.jpg'

    with open(filename, 'rb') as f:
        f_content = list(f.read())

    possible_j = []
    now = 0
    total = 0x4000
    for j in range(0, 0x4000):
        now += 1
        animate(now, total)

        tmp_f_content = f_content.copy()
        size = len(tmp_f_content)

        # 0xFF
        result = tmp_f_content[0] ^ secret[(j + 0) % 0x4000]
        if result != 0xFF:
            continue

        # 0xD8
        result = tmp_f_content[1] ^ secret[(j + 1) % 0x4000]
        if result != 0xD8:
            continue

        # 0xFF
        result = tmp_f_content[2] ^ secret[(j + 2) % 0x4000]
        if result != 0xFF:
            continue

        # 0xFF
        # result = tmp_f_content[size - 1] ^ secret[(j + size - 1) % 0x4000]
        # if result != 0xFF:
        #     continue
        # 
        # # 0xD9
        # result = tmp_f_content[size - 2] ^ secret[(j + size - 2) % 0x4000]
        # if result != 0xD9:
        #     continue

        possible_j.append(j)

    print()
    print('possible j :')
    for j in possible_j:
        print(j)

    j = possible_j[0]

    for idx in range(len(f_content)):
        f_content[idx] ^= secret[(j + idx) % 0x4000]
    
    with open(output_f, 'wb') as f:
        f.write(bytes(f_content))

print('ok')


