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
    - [Classic](#Classic)
    	- [Buffer overflow](#Buffer-overflow)
    	- [Shellcode](#Shellcode)
    	- [Format String Vulnerability](#Format-String-Vulnerability)
    	- [GOT hijack](#GOT-hijack)
    	- [ROP](#ROP)
    	- [ret2plt](#ret2plt)
    	- [ret2libc](#ret2libc)
    	- [ret2dl_resolve](#ret2dl_resolve)
    	- [ret2csu](#ret2csu)
    	- [Stack Migration](#Stack-Migration)
    	- [One Gadget](#One-Gadget)
    - [Heap](#heap)
        - [\_\_malloc_hook & \_\_free_hook hijack](#__malloc_hook--__free_hook-hijack)
        - [Use After Free](#Use-After-Free)
        - [Unsorted bin attack](#Unsorted-bin-attack)
        - [Double Free](#Double-free)
        - [Tcache](#Tcache)
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
**粗體為我正在使用**
- [longld/peda](https://github.com/longld/peda)
    - 始祖
- [**scwuaptx/peda**](https://github.com/scwuaptx/peda)
    - Angelboy 改的, 好看, 還有上下看 code 的功能
- [**scwuaptx/Pwngdb**](https://github.com/scwuaptx/Pwngdb)
    - heap 相關好用的套件
- [cloudburst/libheap](https://github.com/cloudburst/libheap)
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
TBD

### Ghidra
TBD

### radare2
TBD

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
## Classic
### Buffer overflow
各種 Buffer overflow
- stack overflow
    - 經典場景即是利用 stack overflow 蓋掉 return address
    - [AIS3-2018 pwn-mail](https://github.com/LJP-TW/CTF/tree/master/AIS3-2018/pwn-mail)
    - [AIS3-2019 welcomeBof](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/welcomeBof)
    - [Hackme toooomuch](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/toooomuch)
    - [CSAW-2019 baby_boi](https://github.com/LJP-TW/CTF/tree/master/CSAW-2019/Pwn/baby_boi)
    - [CS_2017_Fall 0_pwn1](https://github.com/LJP-TW/CTF/tree/master/CS_2017_Fall/0_pwn1)
    - [CS_2019_Fall bof](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#bof)
    - [CTFZone-2019 Tic-tac-toe](https://github.com/LJP-TW/CTF/tree/master/CTFZone-2019/pwn/Tic-tac-toe)
        - 這題拆分成前後台, 想模擬現實世界的遊戲server, 蠻好玩的
    - [TUCTF-2019 thefirst](https://github.com/LJP-TW/CTF/tree/master/TUCTF-2019/pwn/thefirst)
        - Pwn 入門題
- .data overflow
- heap overflow
- ...

存取超出 array 的範圍導致可以寫到不該寫的位址, 形式也很像是基礎的 Buffer overflow
- [CS_2017_Fall 0_BubbleSort](https://github.com/LJP-TW/CTF/tree/master/CS_2017_Fall/0_BubbleSort)

### Shellcode
經典場景為成功在 rwx 的記憶體區段寫入一段 shellcode, 並跳轉過去執行

x86 syscall 可以查[這篇](https://syscalls.kernelgrok.com/)

x64 syscall 可以查[這篇](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)

- [AIS3-2019 orw](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/orw)
- [Hackme toooomuch2](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/toooomuch2)
- [Hackme onepunch](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/onepunch)
- [CSAW-2018 shell-code](https://github.com/LJP-TW/CTF/tree/master/CSAW-2018/shell-code)
- [AIS3-2019 shellcode-2019](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/shellcode2019)
- [AIS3-2017-Final pwn_100](https://github.com/LJP-TW/CTF/blob/master/AIS3-2017-Final/pwn_100)
- [Pwnable.tw orw](https://pwnable.tw/challenge/#2)
- [CS_2019_Fall orw](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#orw)
- [CS_2019_Fall shellcode](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#shellcode)
- [TUCTF-2019 shellme32](https://github.com/LJP-TW/CTF/tree/master/TUCTF-2019/pwn/shellme32)
    - x86 入門題
- [TUCTF-2019 3step](https://github.com/LJP-TW/CTF/tree/master/TUCTF-2019/pwn/3step)
    - x86 shellcode 小變化題
- [TUCTF-2019 shellme64](https://github.com/LJP-TW/CTF/tree/master/TUCTF-2019/pwn/shellme64)
    - x64 shellcode 小變化題, 要往後 jmp 一點點

### Format String Vulnerability
跟 printf 行為有關, 詳細底層自行 google, 簡單來說, 若 printf 第一個參數可控, 則高機率有此漏洞

- [Hackme echo](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/echo)
- [Hackme echo2](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/echo2)
- [CSAW-2019 GOT_Milk](https://github.com/LJP-TW/CTF/tree/master/CSAW-2019/Pwn/GOT%20Milk)
- [AIS3-2019 hello](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/hello)

利用 Format string vulns leak 出 canary 之後就能打簡單的 BOF
- [CS_2017_Fall 0_ret222](https://github.com/LJP-TW/CTF/tree/master/CS_2017_Fall/0_ret222)

### GOT hijack
跟 linux lazy-binding 的機制有關, 改寫 GOT 表讓下次 function call 到指定位置
- [Hackme leave_msg](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/leave_msg)

將 GOT 改到 Shellcode 上
- [CS_2017_Fall 2_gothijack](https://github.com/LJP-TW/CTF/tree/master/CS_2017_Fall/2_gothijack)
- [CS_2019_Fall casino](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#casino)

將其中一個能控參數是什麼的 function 改成 printf，達到 Format String Vulnerability
- [CS_2019_Fall casino++](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#casino1)

### ROP
可以參考 [ROP輕鬆談](https://www.slideshare.net/hackstuff/rop-40525248)
- [Hackme rop](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/rop)
- [Hackme rop2](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/rop2)
- [Hackme rsbo](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/rsbo)
- [Hackme rsbo2](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/rsbo2)
- [AIS3-2017-Final pwn_200](https://github.com/LJP-TW/CTF/tree/master/AIS3-2017-Final/pwn_200)
- [CS_2019_Fall rop](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#rop)
- [AIS3-2020-EOF-Qual Impossible]待補連結
    - undefined behavior of abs 導致 buffer overflow

以下這題有趣的是 server 亂數的種子是 time(None)，可以跟 server 做一樣的事情就能 bypass 亂數機制
- [AIS3-2019 secureBof](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/secureBof)

### ret2plt
用各種手段(e.g. GOT hijack), 讓 Instruction Pointer 指到 plt，進而 call 到該 plt 的 function

- [CS_2019_Fall ret2plt](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#ret2plt)

### ret2libc
用各種手段(e.g. GOT hijack), 讓 Instruction Pointer 指到 libc 中你想利用的 function 上
- [Hackme stack](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/stack)
- [CS_2019_Fall ret2libc](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#ret2libc)
- [TUCTF-2019 leakalicious](https://github.com/LJP-TW/CTF/tree/master/TUCTF-2019/pwn/leakalicious)

### ret2dl_resolve
TBD.

### ret2csu
可以參考[這篇](https://xz.aliyun.com/t/4068)

主要是指利用 `_libc_csu_init` 的兩個 gadget

- [CS_2019_Fall EDU 2019 election](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#Election)
    - 配合爆破 canary, stack pivoting, ret2csu, rop chain, 蠻好玩的

### Stack Migration
aka stack pivoting，主要是利用 leave 去想辦法控 stack pointer，進而控 return address

結合 ROP、Got Hijack，在 Buffer 長度只夠蓋到 return address 的情況下最終打到 RCE

以下這題的 exploit 不是100%機率成功，為了猜 ASLR 要嘗試好幾次才行
- [CS_2017_Fall 3_readme_150](https://github.com/LJP-TW/CTF/tree/master/CS_2017_Fall/3_readme_150)

### One Gadget
> 這部分需要你先理解 ROP 中 gadget 是什麼
>

libc 中有一些 gadget 跳過去就是開 shell 了

one gadget 可以透過以下工具去查
- [david942j/one_gadget](https://github.com/david942j/one_gadget)

## Heap
打 Heap 題，到目前我的經驗是配著 libc source code 看會好理解很多

[glibc source code](https://ftp.gnu.org/gnu/glibc/)

### \_\_malloc_hook & \_\_free_hook hijack
呼叫 `malloc` 時會先看 `__malloc_hook` 此 function pointer 是否有值，有就 call 它

`free` 也是類似如此

若能竄改這兩個位置，就能控制執行流

為何這類攻擊放在 Heap 底下呢

因為 Heap 類型的攻擊手法常常有許多限制, 其中一種就是 size 限制

從 fastbin 拿一塊記憶體時, 拿出前會比對 size 是不是對的

所以要 fake chunk 還要顧慮這點

剛好, 這些 hook 的前前後後的點, 會滿足這一點, 很適合拿來當 fake chunk

多說無益, 請直接看實例

- [CS_2019_Fall Note](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#Note)
    - 搭配 double free, 成功在 `__malloc_hook - 0x13` 生出 fake chunk, 進而 rewrite `__malloc_hook` 為 `system`

### Use After Free
已經 Free 掉了, 卻還拿來做使用
- [CS_2019_Fall UAF](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#UAF)

### Unsorted bin attack
其實明確定義我不是很了, 應該是任何跟 unsorted bin 相關的攻擊吧(?

- 用 **unsorted bin attack** 讓 `__free_hook` 前面一點點的地址跑出 `0x7fxxxxxx`, 搭配 **fastbin attack** 能改寫到 `__free_hook`
    - [CS_2019_Fall Note++](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg#Note1)
        - 有簡單的 Heap overflow 可利用
    - [BamboofoxCTF-2019 note](https://github.com/LJP-TW/CTF/tree/master/BamboofoxCTF2019/pwn/note)
        - 錯誤使用 snprintf 導致有 Heap overflow 可利用, cool

### Double free
同一塊 chunk free 兩次, 又成功 malloc 再次拿取到這塊 chunk 時

這塊 chunk 就處於 used 與 free 的疊加態當中

如此就有機會爆改 metadata, 改掉 fd bk 鏈, 諸如此類的利用

- [AIS3-2020-EOF-Qual re-alloc]待補連結
    - 玩爆 realloc 的一題, 歸類在這區好像也還是怪怪的 XD

### Tcache
libc 2.26 後增進效能的機制，因為 Tcache 上沒有安全檢查，反而更好打了
- [Pwnable.tw Tcache_Tear](https://pwnable.tw/challenge/#33)
- [CS_2019_Fall T-Note](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#T-Note)
    - Tcache 的 double free 超好打的啦

## Others
- 利用 Smash Stack 錯誤訊息來造成一次性任意讀
    - [Hackme smashthestack](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/smashthestack)
- x64 syscall 322: stub_execveat
    - [AIS3-2019 ppap](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/ppap)


###### tags: `CTF`




