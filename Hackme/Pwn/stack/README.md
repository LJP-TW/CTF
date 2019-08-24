# Return to libc
1. Leak libc address
  - Use stack_pop to leak __libc_start_main address
      - Get system() address
2. Ret to system
  - Write "/bin/sh"

## Stack Frame:
```
0xffffc508: stack.n
0xffffc64c: stack canary
0xffffc65c: ecx 0xffffc680
0xffffc660: ebx
0xffffc664: edi
0xffffc668: ebp
0xffffc67c: ret <__libc_start_main + 247>
```
