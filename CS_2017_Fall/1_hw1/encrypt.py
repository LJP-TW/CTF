plain = raw_input('> ')
result = ''
for i in range(len(plain)):
    v4 = (i + 1) << (i + 2) % 0xa
    v5 = ord(plain[i])
    print(hex(v4 * v5 + 9011))
