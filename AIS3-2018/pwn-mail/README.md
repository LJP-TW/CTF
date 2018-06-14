這題用 gdb 進去後, 看到 registers 都是 R 開頭

**Yeah 64bits**

然後看一下 main

```
0x0000000000400858 <+86>:	lea    rax,[rbp-0x20]
0x000000000040085c <+90>:	mov    rdi,rax
0x000000000040085f <+93>:	mov    eax,0x0
0x0000000000400864 <+98>:	call   0x400650 <gets@plt>
0x0000000000400869 <+103>:	mov    edi,0x400986
0x000000000040086e <+108>:	mov    eax,0x0
0x0000000000400873 <+113>:	call   0x400630 <printf@plt>
0x0000000000400878 <+118>:	lea    rax,[rbp-0x340]
0x000000000040087f <+125>:	mov    rdi,rax
0x0000000000400882 <+128>:	mov    eax,0x0
0x0000000000400887 <+133>:	call   0x400650 <gets@plt>
0x000000000040088c <+138>:	mov    eax,0x0
0x0000000000400891 <+143>:	leave  
0x0000000000400892 <+144>:	ret
```

**Yeah 原來是用 gets 的部分啊** ~~還用兩次~~

再來在 gdb 敲一下 checksec 看一下

```
CANARY    : disabled
```

**Yeah 原來是不保護 stack 的部分啊**

到目前為止, 嗯

# 就決定是 stack overflow 了

正當我在想

~~可是要跳到哪啊, 該不會要自己先塞個 shellcode 再自己跳過去~~

~~不對啊 有啟用NX~~

~~怎辦RRRRR~~

的時候, 看到了

**disas reply**

歐歐歐歐 原來是直接印出 flag 的 function 啊

那就跳過去吧 (((o(\*ﾟ▽ﾟ\*)o)))

實際的部分就看 exploit.py 吧~



