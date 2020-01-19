# Write-up
這題我最終的思路是

第一次 input 時
透過 rcx, 可以 leak 出 libc base address
透過 rbp, rsp, 可以知道 stack 位址

所以讓 hello() call read(stdin, Stack 中其中一個位址, 夠大的size) 是可行的
最終花了 48 Bytes 建構 payload1
再更新一下剛剛的 read 為 read(stdin, RSP+0x48, 夠大的size)
如此一來
第二次的 read 就會將輸入存放在 payload1 最後的 call r8 之後

payload2 再餵 shellcode
call r8 結束後, 就會回來執行 shellcode ㄌ

要再一次 call read 的原因是因為 shellcode 中 syscall opcode 為 `0f 05` 
一定會被檢查到
第二次的 call read 就不會有檢查
想輸入啥就輸入啥
