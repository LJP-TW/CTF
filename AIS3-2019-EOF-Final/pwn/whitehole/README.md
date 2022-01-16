AIS3-EOF-Final 2020 - [pwn] whitehole
===
- [Description](#Description)
- [Exploit](#Exploit)
- [Reference](#Reference)

# Description
![](https://i.imgur.com/bbpWfJu.png)

程式內部主要就長這樣
```c
void __noreturn black_hole()
{
  while ( 1 )
  {
    read(0, buf, 0x30uLL);
    myprintf();
  }
}

int myprintf()
{
  return dprintf(fd, buf);
}
```

而 whitehole 這題的 fd 為 1, 所以看得到輸出

# Exploit
大致的步驟是
1. 首先可以先簡單的 leak 出 libc 和 stack
2. 把 one-gadget 寫到 `__malloc_hook`
3. 呼叫 `malloc` 觸發 one-gadget

問題在於怎麼實現第2步

若 buf 是區域變數, 就簡單多了
- 可以直接把 address 寫進 stack
- 就能用類似 `%8$n` 直接寫入 address

但這題 buf 是公共變數
- 輸入的 payload 不會存在在 stack 上
- 所以無法用類似 `%8$n` 寫入 address

觀察一下在 call `dprintf` 之前的 stack 長相
```
──────────────────────────────────────────── Stack ────────────────────────────────────────────
0000| 0x7fffffffe4d0 --> 0x7fffffffe4e0 --> 0x7fffffffe4f0 --> 0x555555555220 (<__libc_csu_init>:	push   r15)
0008| 0x7fffffffe4d8 --> 0x5555555551fa (<black_hole+36>:	jmp    0x5555555551da <black_hole+4>)
0016| 0x7fffffffe4e0 --> 0x7fffffffe4f0 --> 0x555555555220 (<__libc_csu_init>:	push   r15)
0024| 0x7fffffffe4e8 --> 0x555555555214 (<main+24>:	mov    eax,0x0)
0032| 0x7fffffffe4f0 --> 0x555555555220 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4f8 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax)
0048| 0x7fffffffe500 --> 0x1 
0056| 0x7fffffffe508 --> 0x7fffffffe5d8 --> 0x7fffffffe7fe ("/host/mnt/hgfs/Share/CTF/AIS3-2020-EOF-Final/pwn/whitehole/whitehole")
```
可以觀察到
- `rsp+0`: 指向 `rsp+0x10`

我們可以
- 把 `rsp+0` 視為**指向一個pointer的pointer**
- 把 `rsp+0x10` 視為**指向任意位址的pointer**

透過以下步驟來寫資料到任意位址中
- 先用 `%5$hhn` 來改寫 `rsp+0x10` 中的 1 byte, 使其**指向任意位址**
- 再用 `%7$hhn` 來改寫任意位址中的 1 byte

我這邊的打法是先準備好
- 把 `rsp+0x18` 改成 `__malloc_hook`
- 把 `rsp+0x20` 改成 `__malloc_hook` + 2
- 把 `rsp+0x28` 改成 `__malloc_hook` + 4
- 把 `rsp+0x30` 改成 `__malloc_hook` + 8

再以 `%8$hn` ~ `%11$hn` 將 one-gadget 寫到 `__malloc_hook`

# Reference
https://frozenkp.github.io/pwn/format_string/#argv-chain

###### tags: `CTF`