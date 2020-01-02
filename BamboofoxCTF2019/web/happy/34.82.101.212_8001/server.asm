%include "socket.asm"
%include "utils.asm"
%include "http.asm"
%include "log.asm"

global _start

;===========================================

section .data

port:
    dq 8888

timespec:
    dq 10
    dq 0

;===========================================

section .bss

socket:
    resq 1

sockfd:
    resq 1

;===========================================

section .text

_start:
    enter 0, 0

    ; fork a server
    mov rdi, server
    call fork

    call log_start

    ; read Enter
nonstop:
    mov rax, 35 ; sys_nanosleep
    mov rdi, timespec
    mov rsi, 0
    syscall
    jmp nonstop

    call log_stop

    call exit

server:

    call set_daemon

    ; socket_create() -> socket
    call socket_create
    mov [socket], rax

    ; make port reusable
    mov rdi, rax
    call socket_reuse_port

    ; socket_bind(socket, port)
    mov rdi, [socket]
    mov rsi, [port]
    call socket_bind

    ; socket_listen(socket)
    mov rdi, [socket]
    call socket_listen

    call log_listening

accept:

    ; socket_accept(socket) -> sockfd
    mov rdi, [socket]
    call socket_accept
    mov [sockfd], rax

    call log_connect

    ; fork a subprocess for the client
    mov rdi, client
    call fork

    ; close sockfd for parent
    mov rdi, [sockfd]
    call close_fd

    ; repeat accepting another client
    jmp accept

    call exit

client:

    call set_daemon

client_start:

    ; read and response
    call response
    cmp rax, 0
    je client_start ; keep reading if not EOF

    call log_disconnect
    
    ; close socket fd
    mov rdi, [sockfd]
    call close_fd

    call exit
