AIS3-EOF-Qual 2020 - [Pwn] Impossible
===
- [Description](#Description)
- [Vulns](#Vulns)
- [Exploit](#Exploit)

# Description
![](https://i.imgur.com/FOIu7EL.png)

![](https://i.imgur.com/EwTFfPl.png)

題目給了 `libc-2.27.so`, 以此判斷可運行在 ubuntu 18.04

# Vulns
漏洞在於若 len 為 0x80000000

因為 signed bit 為 1, 判斷為符合 `len < 0`, 執行了 `abs( len )`

而 `abs` 的行為是取 2 的補數

0x80000000 取 2 的補數仍舊是 0x80000000

因為 signed bit 為 1, 所以不符合 `len > 0x100`, 就不會被改為 0x100

如此就有 buffer overflow 了

# Exploit
因為 Canary disabled, 所以可以打 Buffer overflow

PIE disabled, 所以能事先知道各個 plt & got 

適合打一個 ROP 路線

第一條 ROP Chain 串出
- 輸出 libc 位址
- 讀輸入到 `writehere`(隨意挑一個 bss 可寫區段)
- rbp 設定為 `writehere - 8`, leave 後 rsp 會跑到 `writehere`, ret 就能進到第二條 ROP Chain

第二條 ROP Chain 串出 `system('/bin/sh')` 就 pwn 下來ㄌ

###### tags: `CTF`