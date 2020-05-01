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
    	- [ROP](#rop)
    	- [ret2plt](#ret2plt)
    	- [ret2libc](#ret2libc)
    	- [ret2dl_resolve](#ret2dl_resolve)
    	- [ret2csu](#ret2csu)
    	- [Stack Migration](#Stack-Migration)
    	- [One Gadget](#One-Gadget)
    - [Heap](#heap)
        - [\_\_malloc_hook & \_\_free_hook hijack](#__malloc_hook--__free_hook-hijack)
        - [Use After Free](#Use-After-Free)
        - [Fastbin attack](#Fastbin-attack)
        - [Unsorted bin attack](#Unsorted-bin-attack)
        - [Double Free](#Double-free)
        - [Unlink](#Unlink)
        - [malloc consolidate](#malloc-consolidate)
        - [House of Spirit](#House-of-Spirit)
        - [Tcache](#Tcache)
    - [Windows Pwn](#Windows-Pwn)
        - [ROP](#rop-1)
    - [Others](#Others)
        - [FILE structure](#FILE-structure)
        - [Parent & Child](#parent--child)

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
    - [angstromCTF-2020 Deja_vu](https://github.com/LJP-TW/CTF/tree/master/angstromCTF-2020/pwn/Deja%20Vu)
        - File 的 race condition 造成簡單的 BoF
        - 用到 ctypes module 中的 CDLL，來製造出跟 process 一樣的 random number
    - [angstromCTF-2020 No_Canary](https://github.com/LJP-TW/CTF/tree/master/angstromCTF-2020/pwn/No%20Canary)
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
- [angstromCTF-2020 LIBrary_in_C](https://github.com/LJP-TW/CTF/tree/master/angstromCTF-2020/pwn/LIBrary%20in%20C)

利用 Format string vulns leak 出 canary 之後就能打簡單的 BOF
- [CS_2017_Fall 0_ret222](https://github.com/LJP-TW/CTF/tree/master/CS_2017_Fall/0_ret222)
- [angstromCTF-2020 Canary](https://github.com/LJP-TW/CTF/tree/master/angstromCTF-2020/pwn/Canary)

二段 Format string vulns
- [AIS3-2020-EOF-Final whitehole](https://github.com/LJP-TW/CTF/tree/master/AIS3-2020-EOF-Final/pwn/whitehole)
- [AIS3-2020-EOF-Final blackhole](https://github.com/LJP-TW/CTF/tree/master/AIS3-2020-EOF-Final/pwn/blackhole)
    - 盲打, 成功機率為 1/256

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
- [AIS3-2019 secureBof](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/secureBof)
    - 這題有趣的是 server 亂數的種子是 time(None)，可以跟 server 做一樣的事情就能 bypass 亂數機制
- [CS_2019_Fall rop](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#rop)
- [AIS3-2020-EOF-Qual Impossible](https://github.com/LJP-TW/CTF/tree/master/AIS3-2020-EOF-Qual/pwn/Impossible)
    - undefined behavior of abs 導致 buffer overflow
- [AIS3-2020-EOF-Qual EasyROP](https://github.com/LJP-TW/CTF/tree/master/AIS3-2020-EOF-Qual/pwn/EasyROP)
    - x86 ROP
    - 使用 libc 中的 `call   DWORD PTR gs:0x10` gadget, 進而呼叫了 `__kernel_vsyscall`, 作為 `int 0x80` 的替代方案
    - 在 x64 編譯 x86 程式時, function prologue 長得不太一樣, 造成 ROP 的困難
    - EasyROP 超不 Easy @@

### ret2plt
用各種手段(e.g. GOT hijack), 讓 Instruction Pointer 指到 plt，進而 call 到該 plt 的 function

- [CS_2019_Fall ret2plt](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#ret2plt)

### ret2libc
用各種手段(e.g. GOT hijack), 讓 Instruction Pointer 指到 libc 中你想利用的 function 上
- [Hackme stack](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/stack)
- [CS_2019_Fall ret2libc](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#ret2libc)
- [TUCTF-2019 leakalicious](https://github.com/LJP-TW/CTF/tree/master/TUCTF-2019/pwn/leakalicious)

### ret2dl_resolve
[這篇其他人的筆記](http://pwn4.fun/2016/11/09/Return-to-dl-resolve/)寫得很詳細

我將其更進一步簡化成[這篇筆記](https://hackmd.io/@LJP/BkJmAqXEI)

利用 `_dl_runtime_resolve` 這個用來支援 Lazy binding 機制的函數，可以在沒有 leak libc 的情況之下直接 call system

- [XDCTF-2015 pwn 200](https://github.com/LJP-TW/CTF/tree/master/XDCTF-2015/pwn/200)
    - 參考這題的 exploit 能對這個攻擊有更好的理解


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
- [ByteBanditsCTF-2020 write](https://github.com/LJP-TW/CTF/tree/master/ByteBanditsCTF-2020/pwn/write)
    - 寫 stack 使 one-gadget 的條件能夠滿足

### Use After Free
已經 Free 掉了, 卻還拿來做使用
- [CS_2019_Fall UAF](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#UAF)
- [AIS3-2020-EOF-Final TT](https://github.com/LJP-TW/CTF/tree/master/AIS3-2020-EOF-Final/misc/TT)

### Fastbin attack
- [9447-ctf-2015 search-engine](https://github.com/LJP-TW/CTF/tree/master/9447-ctf-2015/pwn/search-engine)
    - 參考 [shellphish/how2heap](https://github.com/shellphish/how2heap) 而去練習的題目, 將 fake chunk 建到 stack 上, 達到類似 stack overflow 的效果, 後續建 ROP chain 達到 RCE
- [0ctf-quals-2017 BabyHeap2017](https://github.com/LJP-TW/CTF/tree/master/0ctf-quals-2017/pwn/BabyHeap2017)
    - 有簡單的 heap overflow
    - 將其中一個 chunk 的 size 改掉後 free 他, 做出 unsorted bin, 再申請一塊適當大小的 chunk 讓下一次申請的 chunk 被兩個 pointer 指著
    - 改 `__malloc_hook` 為 one gadget 拿 shell

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

- [AIS3-2020-EOF-Qual re-alloc](https://github.com/LJP-TW/CTF/tree/master/AIS3-2020-EOF-Qual/pwn/re-alloc)
    - 玩爆 realloc 的一題, 歸類在這區好像也還是怪怪的 XD

### Unlink
利用 unlink 機制寫入符合條件的位址 (通常是 scope 為全域變數的 pointer)
- [Nullcon-2020 Dark_Honya](https://github.com/LJP-TW/CTF/tree/master/Nullcon-2020/pwn/Dark%20Honya)
- [HitconCTF-2014 stkof](https://github.com/LJP-TW/CTF/tree/master/HitconCTF-2014/pwn/stkof)
- [Insomni'hack-2017 Wheel_of_Robots](https://github.com/LJP-TW/CTF/tree/master/Insomni'hack-2017/pwn/Wheel%20of%20Robots)

### Off-By-One
在 heap 上只 overflow 了 1 byte，通常就是蓋 Null 截斷字串，清除了下個 chunk 的 size 中的 prev_in_use bit

有機會製造出 chunk overlapping 和 UAF
- [PlaidCTF-2015 datastore](https://github.com/LJP-TW/CTF/tree/master/PlaidCTF-2015/pwn/datastore)

### malloc consolidate
- [HitconCTF-2016 SleepyHolder](https://github.com/LJP-TW/CTF/tree/master/HitconCTF-2016/SleepyHolder)
    - 申請超大塊 chunk, 觸發 `malloc_consolidate()`
    - 利用 `malloc_consolidate()` 會將已經 free 掉的 fastbin A chunk 整合後放回 smallbin, 讓緊鄰著的下一塊 B chunk (為 small chunk) 的 `PREV_INUSE` bit 為 0
    - 再次 free A chunk, 此時由於它已被轉移到 smallbin, 不會導致 double free 被檢測到
    - 此時 A chunk 同時處於 fastbin 和 smallbin 
    - 再次申請 A chunk, 做好 unlink 的準備
    - Free B chunk, 此時 B chunk 以為緊鄰著的上一塊 chunk 是 free 的, 會跟上一塊 chunk 合併
    - unlink 導致任意寫
    - 後面就是自由發揮了

### House of Spirit
free 一個剛好符合 chunk 結構的位置, 下次再度申請記憶體時就能真的寫到這塊 fake chunk 了

- [hackluCTF-2014 oreo](https://github.com/LJP-TW/CTF/tree/master/hackluCTF-2014/pwn/oreo)
    - bss段上的全域變數經過刻意的調整後, 變成一塊可以被 free 的 fake chunk
    - free 後再度申請, 就能隨意寫全域變數

### Tcache
libc 2.26 後增進效能的機制，因為 Tcache 上沒有安全檢查，反而更好打了
- [Pwnable.tw Tcache_Tear](https://pwnable.tw/challenge/#33)
- [CS_2019_Fall T-Note](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg?view#T-Note)
    - Tcache 的 double free 超好打的啦

## Windows Pwn
玩法大同小異, 但 Windows 多了 SEH 機制

### ROP
- [AIS3-2020-EOF-Qual BlueNote](https://github.com/LJP-TW/CTF/tree/master/AIS3-2020-EOF-Qual/pwn/BlueNote)
    - 基礎 ROP 題, 打 Linux pwn 通常會要 leak `libc`, 而 Windows pwn 則是 leak `kernel32.dll` `ntdll.dll`
    - 用 IDA pro 開這些 dll, 從 `Export` 中找到想要的 function offset
    - Windows calling convention 是 `rcx` `rdx` `r8` `r9` `stack` ...
    - 用 Windbg 動態執行, 入門可以從[這篇](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step)開始

## Others
- 利用 Smash Stack 錯誤訊息來造成一次性任意讀
    - [Hackme smashthestack](https://github.com/LJP-TW/CTF/tree/master/Hackme/Pwn/smashthestack)
- x64 syscall 322: stub_execveat
    - [AIS3-2019 ppap](https://github.com/LJP-TW/CTF/tree/master/AIS3-2019/pwn/ppap)
- [ByteBanditsCTF-2020 look-beyond](https://github.com/HexRabbit/CTF-writeup/tree/master/2020/ByteBandits-CTF/look-beyond)
    - malloc 申請很大塊的空間時, 分配到的記憶體會緊貼在 libc 或 ld 之前
    - 而 fs 指向的位址在 ld 後面的記憶體
    - 通過直接改 fs:0x28, 讓程式以為 stack overflow, 進而呼叫 `__stack_chk_fail`

### FILE structure
- [AIS3-2020-EOF-Qual nonono](https://github.com/LJP-TW/CTF/tree/master/AIS3-2020-EOF-Qual/pwn/nonono)
    > 偽造 FILE 結構 (stdin) 做任意寫，把 one_gadget 寫進 free hook

### Parent & Child
- [BalsnCTF-2019 SecureCheck](https://github.com/LJP-TW/CTF/tree/master/BalsnCTF-2019/misc/SecureCheck/release)
    > 寫一份 shellcode 可以在判別 parent/child 後執行不同的指令
    > 
    - rdrand 

### Misc
- [angstromCTF-2020 Bop_It](https://github.com/LJP-TW/CTF/tree/master/angstromCTF-2020/pwn/Bop%20It)
    - read 回傳值為拿了幾個字，並不被 Null 截斷
    - strlen 回傳值以碰到 Null 來判斷
    - 兩者行為的不同造成的 info leak
- [angstromCTF-2020 bookface](https://github.com/LJP-TW/CTF/tree/master/angstromCTF-2020/pwn/bookface)
    - Server 有下一個指令
        - `sysctl vm.mmap_min_addr=0`
        - 意味著能分配出在 0x0 的記憶體
    - 參考 [libc-2.23 rand](https://hackmd.io/6c9p2hkWRBu_ZM6qbEXlzg?view)
        - unsafe_state 的 rand_type 不等於 0 且 rptr 與 fptr 若指向 0，則 rand() 回傳 0
    - 通過改掉 randtbl 中的值，達到上述條件，rand() 回傳 0 後，mmap 創出在 0 的記憶體
    - 在 0 記憶體位址偽造 File structure
    - 在 `fopen(file, "rb")` 之前把 file 砍掉，fopen 就會失敗而回傳 NULL
    - 原本應該用來辨別錯誤的 NULL 變成真的指向一個有效的 File structure
    - 偽造 vtable，將 `_IO_xsgetn_t` 指向 one gadget，fread 就會 call 到 one gadget

###### tags: `CTF`




