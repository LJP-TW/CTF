from pwn import *
import os

maze = []
for y in range(16):
    maze.append([])
    for x in range(16):
        maze[y].append(-1)
maze[0][0] = 0

def outputMaze():
    for y in range(16):
        print(''.join('{0: <3}'.format(k) for k in maze[y]))

# tuple direction
t_direc = [(1, 0), (0, 1), (-1, 0), (0, -1)]
# string direction
s_direc = ['up', 'right', 'down', 'left']
# int direction
i_direc = -1

now_y, now_x = 0, 0
y, x = 0, 0
path = []
isEnd = False
isRestart = True

while isEnd == False:
    outputMaze()
    print path
    print '(' + str(y) + ', ' + str(x) + ')'

    if isRestart:
        r = remote('pre-exam-chals.ais3.org', 10202)
        r.recvline()
        r.recvline()
        y, x = 0, 0
        # print '#### Restart:' + str(path)
        isRestart = False
        for i in path:
            ty, tx = t_direc[i]
            y = y + ty
            x = x + tx
            r.sendline(s_direc[i])
            msg = r.recvline()

    isNew = False
    for i in range(4):
        ty, tx = t_direc[i]
        now_y = y + ty
        now_x = x + tx
        if (0 <= now_x and now_x < 16) and \
           (0 <= now_y and now_y < 16) and \
           (maze[now_y][now_x] == -1):
                isNew = True
                i_direc = i
                break

    while isNew == False:
        if len(path) <= 0:
            print '#### GGGG'
            exit()
        ty, tx = t_direc[path[-1]]
        y = y - ty
        x = x - tx
        path.pop()
        print '(' + str(y) + ', ' + str(x) + ')'

        for i in range(4):
            ty, tx = t_direc[i]
            now_y = y + ty
            now_x = x + tx
            if (0 <= now_x and now_x < 16) and \
               (0 <= now_y and now_y < 16) and \
               (maze[now_y][now_x] == -1):
                    isRestart = True
                    r.close()
                    isNew = True
                    break

    if isRestart:
        continue

    if isNew == True:
        path.append(i_direc)
        r.sendline(s_direc[i_direc])
        msg = r.recvline()
        ty, tx = t_direc[i_direc]
        now_y = y + ty
        now_x = x + tx
        if msg[-3:-1] == 'ok':
            # print '#### (' + str([now_y]) + ',' + str([now_x]) + ') OK'
            maze[now_y][now_x] = 0
            y, x = now_y, now_x
        elif msg[-5:-1] == 'wall':
            # print '#### (' + str([now_y]) + ',' + str([now_x]) + ') WALL'
            path.pop()
            maze[now_y][now_x] = 1
            isRestart = True
            r.close()

            isDeadend = True
            while isDeadend:
                for i in range(4):
                    if ((i + 2) % 4) == i_direc:
                        continue
                    ty, tx = t_direc[i]
                    now_y = y + ty
                    now_x = x + tx
                    if (0 <= now_x and now_x < 16) and \
                       (0 <= now_y and now_y < 16) and \
                       (maze[now_y][now_x] == -1 or maze[now_y][now_x] == 0):
                            isDeadend = False
                            break
                if isDeadend:
                    maze[y][x] = 1
                    ty, tx = t_direc[path[-1]]
                    y = y - ty
                    x = x - tx
                    path.pop()
        else:
            print msg
            exit()
    else:
        print '#### GG'
        exit()

