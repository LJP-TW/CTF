from pwn import *

isEnd = False
direction = ['up', 'right', 'down', 'left']
path = [1, 0, 0, 0, 0, 3, 0, 0, 1, 1]

r = remote('pre-exam-chals.ais3.org', 10202)
msg = r.recvline()
print msg
msg = r.recvline()
print msg
for i, s in enumerate(path):
    print(str(i) + ' => ' + str(s))
    r.sendline(direction[s])
    msg = r.recvline()
    print msg

