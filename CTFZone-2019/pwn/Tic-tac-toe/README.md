CTFZone 2019 - [Pwn] Tic-tac-toe
===
- [Description](#Description)
- [ScreenShot](#ScreenShot)

# Description
給了兩支程式

- server.py
    - 後端 server
- tictactoe
    - 前端 server

架構是玩家連線到前端 server, 前台會向後台為此玩家申請 Token

後台記錄著玩家們各贏了幾次, 贏了100次以上後, 若前台要求 flag 後台才會給

tictactoe 保護機制如下

![](https://i.imgur.com/tO6ROMq.png)

分析一下程式, 找到明顯的 Buffer Overflow

![](https://i.imgur.com/MSc01Zz.png)

`tmp_name` 只有 16 bytes, 但卻可以輸入 2048 bytes 進去, 導致執行流可控

首先為了能在 local 測試, 我先 patch 了 tictactoe, 讓它後台不是連 `task2-tictactoe-backend` 這個 hostname, patch 成 `localhost`

再來就是偽造打往後台的 request, 偽造出勝利的部分, 並loop超過100次, 之後拿 flag

但 shellcode 不能有 0x00, 否則會被截斷, 所以部分 shellcode 看起來很冗的原因是在 bypass 這個限制

實際打的時候會需要跑一陣子

# ScreenShot
![](https://i.imgur.com/BkaKdNz.png)

![](https://i.imgur.com/TNdfnAa.jpg)


###### tags: `CTF`