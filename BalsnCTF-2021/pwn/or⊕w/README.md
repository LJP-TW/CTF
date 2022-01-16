# Pwn / 313 - or⊕w

> No more orw for you :(

## Solution
By [@LJP](https://github.com/LJP-TW)
Credits to [@wxrdnx](https://github.com/wxrdnx), [@HexRabbit](https://github.com/HexRabbit), [@jaidTw](https://github.com/jaidTw)

* 題目十分簡短

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rbp
  char v5[16]; // [rsp-18h] [rbp-18h]
  __int64 v6; // [rsp-8h] [rbp-8h]

  __asm { endbr64 }
  v6 = v3;
  setbuf(_bss_start, 0LL);
  puts("Can you defeat orxw?");
  if ( read(0, v5, 0x400uLL) <= 0 )
    _exit(-1);
  if ( fork() )
  {
    wait((__WAIT_STATUS)0x40408CLL);
    seccomp_parent();
  }
  else
  {
    close(0);
    close(1);
    close(2);
    seccomp_child();
  }
  return 0;
}
```

* parent 的 rule 如下

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0008
 0006: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0008
 0007: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
```

* child 的 rule 如下
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0010
 0007: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0010
 0008: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0010
 0009: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

* 總體來說, 打法是
    1. 想辦法讓 parent 跟 child 執行到不同的東西
    2. child open read flag, 想辦法將 flag 資訊以 exit code 的方式告訴 parent
    3. parent 把 child exit code write 出來, 我們就能得到 flag 資訊

* 幾個關鍵點
    * 判斷 wstatus 如果不是 0 (parent) 就跳到 rax，如果是 0 (child) 就繼續 rop。
    * 造出 if else 之後直接在 child side channel 解

* 以後 ropper 跟 ROPgadget 都要用, 一開始一直找不到 `add dword ptr [rbp - 0x3d], ebx ; nop ; ret` 這個 gadget

