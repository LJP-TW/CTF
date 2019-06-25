from pwn import *

isEnd = False
direction = ['up', 'right', 'down', 'left']
path = [1, 0, 0, 0, 0, 3, 0, 0, 1, 1, 1, 2, 2, 2, 2, 2, 2, 1, 1]
now = len(path)


for i in range(256 - len(path)):
    path.append(-1)

while isEnd == False:
    r = remote('pre-exam-chals.ais3.org', 10202)
    r.recvline()
    r.recvline()
    path[now] += 1
    for i, s in enumerate(path):
        print(str(i) + ' => ' + str(s))
        r.sendline(direction[s])
        msg = r.recvline()
        if msg[-3:-1] == 'ok':
            print('#### OK')
            if i >= now:
                now += 1
                path[now] += 1
            print path
        elif msg[-5:-1] == 'wall':
            print('#### WALL')
            r.close()
            break

        print msg
print i

