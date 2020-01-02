;===========================================

section .text

;-------------------------------------------
; socket_create()
;   Create socket and return it.
; Return:
;   rax -- socket

socket_create:
    mov rax, 41     ; sys_socket
    mov rdi, 2	    ; AF_INET
    mov rsi, 1      ; SOCK_STREAM
    mov rdx, 0      ; IPPROTO_TCP
    syscall
    ret

;-------------------------------------------
; socket_bind(socket, port)
;   Bind socket to a port.
; Args:
;   rdi -- socket
;   rsi -- port

socket_bind:
    ; bind(
    ;       socket (return by socket_create),
    ;       {   AF_INET = 2 (2 bytes),
    ;           port (2 bytes),
    ;           INADDR_ANY = 0 (4 bytes)
    ;       },
    ;       16
    ; )
    enter 0, 0
    mov ebx, esi
    xor rcx, rcx
    mov cl, bl
    shl ecx, 8
    mov cl, bh
    shl ecx, 16
    mov cx, 0x0002
    push rcx        
    mov rsi, rsp    ; &sa
    mov rdx, 16     ; sizeof(sa)
    mov rax, 49     ; sys_bind
    syscall
    leave
    ret

;-------------------------------------------
; socket_reuse_port(socket)
;   Make port reusable.
; Args:
;   rdi -- socket

socket_reuse_port:
    enter 0, 0
    push qword 1    ; true
    mov rax, 54     ; sys_setsockopt
    mov rsi, 1      ; SOL_SOCKET
    mov rdx, 2      ; SO_REUSEPORT=2
    mov r10, rsp    ; &true
    mov r8, 8       ; 8 bytes
    syscall
    leave
    ret           

;-------------------------------------------
; socket_listen(socket)
;   Start listening.
; Args:
;   rdi -- socket

socket_listen:
    ; listen(socket, 0);
    mov rax, 50     ; sys_listen
    xor rsi, rsi    ; 0
    syscall
    ret

;-------------------------------------------
; socket_accept(socket)
;   Accept a client, return it's file descriptor.
; Args:
;   rdi -- socket
; Return:
;   rax -- file descriptor

socket_accept:
    ; accept(socket, 0, 0);
    xor rsi, rsi    ; rsi = 0
    xor rdx, rdx    ; rdx = 0
    mov rax, 43     ; rax = sys_accept
    syscall
    ret
