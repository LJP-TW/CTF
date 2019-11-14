CTF Pwn Note
===
- [流程](#流程)
    - [架設題目](#架設題目)
        - [ncat](#ncat)
            - [安裝](#安裝)
            - [使用](#使用)
    - [分析工具](#分析工具)
        - [gdb](#gdb)
            - [套件](#套件)
            - [使用方式](#使用方式)
        - [seccomp-tools](#seccomp-tools)
        - [IDA](#IDA)
        - [Ghidra](#Ghidra)
        - [radare2](#radare2)
    - [寫 exploit](#寫-exploit1)
        - [Python 套件](#Python-套件)
        - [確定 libc 版本](#確定-libc-版本)
        - [不同版本 libc](#不同版本-libc)
        - [配上動態分析](#配上動態分析)
- [攻擊手段](#攻擊手段)
    - [Buffer overflow](#Buffer-overflow)
    - [Shellcode](#Shellcode)
    - [Format String Attack](#Format-String-Attack)
    - [ROP](#ROP)
    - [GOT hijack](#GOT-hijack)
    - [ret2lib](#ret2lib)
    - [Others](#Others)

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

## Buffer overflow
各種 Buffer overflow
- stack overflow
    - 經典場景即是利用 stack overflow 蓋掉 return address
    - [AIS3-2018 pwn-mail](https://github.com/LJP-TW/CTF/tree/master/AIS3-2018/pwn-mail)
    - [AIS3-2019 welcomeBof](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/welcomeBof)
    - [Hackme toooomuch](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/toooomuch)
    - [CSAW-2019 baby_boi](https://github.com/LJP-TW/CTF/tree/master/CSAW-2019/Pwn/baby_boi)
- .data overflow
- heap overflow
- ...

## Shellcode
經典場景為成功在 rwx 的記憶體區段寫入一段 shellcode, 並跳轉過去執行
- [AIS3-2019 orw](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/orw)
- [Hackme toooomuch2](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/toooomuch2)
- [Hackme onepunch](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/onepunch)
- [CSAW-2018 shell-code](https://github.com/LJP-TW/CTF/tree/master/CSAW-2018/shell-code)
- [AIS3-2019 shellcode-2019](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/shellcode2019)
- [AIS3-2017-Final pwn_100](https://github.com/LJP-TW/CTF/blob/master/AIS3-2017-Final/pwn_100)

## Format String Attack
跟 printf 行為有關, 詳細底層自行 google, 簡單來說, 若 printf 第一個參數可控, 則高機率有此漏洞

- [Hackme echo](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/echo)
- [Hackme echo2](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/echo2)
- [CSAW-2019 GOT_Milk](https://github.com/LJP-TW/CTF/tree/master/CSAW-2019/Pwn/GOT%20Milk)
- [AIS3-2019 hello](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/hello)

## ROP
可以參考 [ROP輕鬆談](https://www.slideshare.net/hackstuff/rop-40525248)
- [Hackme rop](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/rop)
- [Hackme rop2](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/rop2)
- [Hackme rsbo](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/rsbo)
- [Hackme rsbo2](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/rsbo2)
- [AIS3-2019 secureBof](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/secureBof)
- [AIS3-2017-Final pwn_200](https://github.com/LJP-TW/CTF/tree/master/AIS3-2017-Final/pwn_200)

## GOT hijack
跟 linux lazy-binding 的機制有關, 改寫 GOT 表讓下次 function call 到指定位置
- [Hackme leave_msg](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/leave_msg)

## ret2lib
用各種手段, 讓 Instruction Pointer 指到 libc 中你想利用的 function 上
- [Hackme stack](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/stack)

## Others
- 利用 Smash Stack 錯誤訊息來造成一次性任意讀
    - [Hackme smashthestack](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/smashthestack)
- x64 syscall 322: stub_execveat
    - [AIS3-2019 ppap](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/ppap)


###### tags: `CTF`




