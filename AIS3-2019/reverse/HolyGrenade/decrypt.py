from hashlib import md5


cs = ['ba3a7f3bd92a5d418f5e16886db62674', # AIS3
    '33e4500b205b80e52dd52e796cba8b7d',
    '7d1c09bbf2025facf6bd0fec0ec6a780',
    '9cedd8dee7b5b87838d7a9bed76df8e5',
    '764d30cb4807c5a870a47b53be6cf662',
    'f1e8fda6c3ff87e43905ea1690624c64',
    'd7939cb11edaa9b1fb05efb4e2946f75',
    '5ae001ebd955475c867617bdb72e7728']

def reverse_OO0o(arg):
    arg = bytearray(arg, 'ascii')
    for i in range(0, len(arg), 4):
        a = arg[i]
        b = arg[i + 1]
        c = arg[i + 2]
        d = arg[i + 3]
        arg[i] = b
        arg[i + 1] = d
        arg[i + 2] = a
        arg[i + 3] = c
    return arg.decode('ascii')

for i in range(0, len(cs)):
    cs[i] = reverse_OO0o(cs[i])
    print(cs[i])
# cand = list('AIS3')
cand = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPWRSTUVWXYZ1234567890!@#$%&()<>/~,- _{}')
flag = ''

# temp = [ord('A'), ord('I'), ord('S'), ord('3')]
# print(md5(bytes(temp[0:4])).hexdigest())

for index, c in enumerate(cs):
    i = [0, 0, 0, 0]
    temp = [ord(cand[i[0]]), ord(cand[i[1]]), ord(cand[i[2]]), ord(cand[i[3]])]
    while md5(bytes(temp)).hexdigest() != c:
        i[3] += 1
        if i[3] >= len(cand):
            i[2] += 1
            i[3] = 0
            if i[2] >= len(cand):
                i[1] += 1
                i[2] = 0
                if i[1] >= len(cand):
                    i[0] += 1
                    i[1] = 0
                    if i[0] >= len(cand):
                        print('GG')
                        exit()
        temp = [ord(cand[i[0]]), ord(cand[i[1]]), ord(cand[i[2]]), ord(cand[i[3]])]
    for f in i:
        flag += cand[f]
    print(flag)
    
