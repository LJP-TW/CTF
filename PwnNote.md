---
title: CTF Pwn Note
description: Pwn
tags: CTF
lang: zh_tw
---

CTF Pwn Note
===
[TOC]

# 流程

## 架設題目
### ncat
#### 安裝
```shell
sudo apt-get install nmap
```
ncat 是 nmap 底下的工具之一
#### 使用
```shell
ncat -kvl [port] -c [command]
```
可以在最後加上 `&` 背景執行
keyword: `linux fg`

## 分析工具

### gdb

#### 套件
- [peda](https://github.com/longld/peda)
- [libheap](https://github.com/cloudburst/libheap)
    - 照著官方 installGuide 跑就可以，只是可能要自行更改對應的`~/.local/lib/python3.4/site-packages/` 路徑
    

#### 使用方式

##### 動態 Debug
- Attach 到已經 run 起來的 process
    ```
    sudo gdb at `pidof [program_path]`
    ```
- 自行從頭 debug
    ```
    gdb [program_path]
    ```

##### 中斷點
- b:
    - 設定中斷點
- info b
    - 秀出中斷點資訊
- disab b `[Num]`
    - 將 `[Num]` 號中斷點 disable
- en b `[Num]`
    - 將 `[Num]` 號中斷點 enable
- del br `[Num]`
    - 將 `[Num]` 號中斷點移除

##### 執行
- r

##### 暫存器/Memory
- 賦值
    - set $`[register name]` = `[value]`
        - 設定暫存器的值
        - e.g.
            - set $rbx = 0x1
    - set \*`[memory address]` = `[value]`
        - 設定記憶體上的值
        - e.g.
            - set *0x7fffffffde00 = 0x8787
    - set {char [`[Num]`]} `[memory address]` = "`[String]`"
        - 參考[這篇](https://stackoverflow.com/questions/19503057/in-gdb-how-can-i-write-a-string-to-memory)
        - 寫入任意長度的字串
        - e.g.
            - set {char [4]} 0x08040000 = "Ace"

- 查詢
    - info registers
        - 列出所有暫存器的值
    - info registers [register name]
        - 列出特定暫存器的值
    - x
        - 觀察記憶體的值
        - 參考[完整手冊](https://visualgdb.com/gdbreference/commands/x)

##### 其他
- 與 fork 相關指令
    - show follow-fork-mode
        - 顯示出 fork 後，gdb 會 attach parent 還是 child
    - set follow-fork-mode [mode]
        - mode: parent | child
        - 設定 fork 後會 attach 誰
        - attach 任一個程序後，另一個程序若還未結束都可再用另一個 gdb 去 attach
            - 可參考[這篇 write up](https://hackmd.io/-b0RqwwJTLqbJt7lvsZYUQ)

### seccomp-tools
- https://github.com/david942j/seccomp-tools
- 題目有時跟 seccomp 有關，可以用這個工具來列出設定了哪些規則

### IDA
### Ghidra
### radare2

## 寫 exploit

### Python 套件
https://github.com/Gallopsled/pwntools

### 確定 libc 版本
有時候題目只會給 libc 卻不給是什麼版本，可以這樣找

`strings libcfile.so | grep 'libc-'`

### 不同版本 libc
以下用一個狀況舉例
在 ret2lib 若想 return 到 `_IO_gets`, 但 localhost 的 libc 跟 target host 的版本不同
已知 target host 的 libc 為 libc-2.23.so.i386
透過指令
```shell
readelf -s libc-2.23.so.i386 | grep -E '(main|gets)@@'
```
可以得到 `_IO_gets` `__libc_start_main` 的 address
兩者的 offset 加上 libc 的 base address 就是你該 return 到的位置

### 配上動態分析
可以先打看看自己架的題目

在攻擊的 python 腳本中加 `raw_input('>')` 先讓腳本不要送 request

再用 gdb attach 上已經 run 起來的題目

之後就能好好動態觀察攻擊腳本會在題目中怎麼 run


# 攻擊手段

## ret2lib
用各種手段, 讓 Instruction Pointer 指到 libc 中你想利用的 function 上








