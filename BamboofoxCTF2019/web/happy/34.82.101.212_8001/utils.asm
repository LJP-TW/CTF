;===========================================

section .data

endl:
    db 10, 0

;===========================================

section .bss

file_stat:
    resb 144

dstream_buffer:
    resb 256

;===========================================

section .text

;-------------------------------------------
; fork(addr)
;   Fork a subprocess to execute on addr.
; Args:
;   rdi -- address for subprocess to jmp to

fork:
    mov rax, 57     ; sys_fork
    syscall
    cmp rax, 0      ; child process returns 0
    je fork_sub     ; goto fork_sub if it's a child
    ret

fork_sub:
    pop rax         ; pop to restore rsp
    jmp rdi         ; jmp to the target address

;-------------------------------------------
; set_daemon()
;   Send SIGTERM when parent dies.

set_daemon:
    mov rax, 157    ; sys_prctl
    mov rdi, 1      ; PR_SET_PDEATHSIG
    mov rsi, 15     ; SIGTERM
    syscall
    ret

;-------------------------------------------
; close_fd(fd)
;   Close file descriptor.
; Args:
;   rdi -- file descriptor to close

close_fd:
    mov rax, 3
    syscall
    ret

;-------------------------------------------
; dstream(fd_out, fd_in)
;   Write fd_in to fd_out until EOF.
; Args:
;   rdi -- file descriptor output
;   rsi -- file descriptor input

dstream:
    enter 24, 0
    mov [rbp-8], rdi    ; fd_out
    mov [rbp-16], rsi   ; fd_in
    jmp dstream_read

dstream_write:
    mov rax, 1          ; sys_write
    mov rdi, [rbp-8]    ; fd_out
    mov rsi, dstream_buffer
    mov rdx, [rbp-24]   ; read size
    syscall

dstream_read:
    mov rax, 0          ; sys_read
    mov rdi, [rbp-16]   ; fd_in
    mov rsi, dstream_buffer
    mov rdx, 256
    syscall
    mov [rbp-24], rax   ; read size
    cmp rax, 0
    jg dstream_write
    leave
    ret

;-------------------------------------------
; dputi(fd, integer)
;   Convert integer to string and write it to fd.
; Args:
;   rdi -- target file descriptor
;   rsi -- target integer

dputi:
    enter 32, 0
    mov [rbp-8], rdi        ; fd
    mov [rbp-16], rsi       ; integer
    mov qword [rbp-24], 0   ; clear memory
    mov qword [rbp-32], 0
    lea rdi, [rbp-18]       ; reserve null byte
    mov rax, rsi            ; devidend
    std

dputi_devide:
    xor rdx, rdx
    mov rcx, 10
    div rcx
    mov rsi, rax        ; save quotient
    mov rax, "0"
    add rax, rdx        ; al becomes the digit
    stosb
    mov rax, rsi        ; restore quotient
    cmp rax, 0
    jg dputi_devide     ; repeat if quotient > 0

    inc rdi
    mov rsi, rdi
    mov rdi, [rbp-8]
    call dputs
    leave
    ret

;-------------------------------------------
; puti(integer)
;   Write integer to stdout.
; Args:
;   rdi -- integer

puti:
    mov rsi, rdi
    mov rdi, 1
    call dputi
    ret

;-------------------------------------------
; dputs(fd, *str)
;   Put string to some file descriptor.
; Args:
;   rdi -- the target file descriptor
;   rsi -- address of string

dputs:
    enter 16, 0
    mov [rbp-8], rdi
    mov [rbp-16], rsi
    mov rdi, rsi
    call strlen
    mov rdx, rax
    mov rax, 1
    mov rdi, [rbp-8]
    mov rsi, [rbp-16]
    syscall
    leave
    ret

;-------------------------------------------
; puts(*str)
;   Write string to stdout.
; Args:
;   rdi -- address of string

puts:
    mov rsi, rdi
    mov rdi, 1
    call dputs
    ret

;-------------------------------------------
; strlen(*str)
;   Return length of null ended string.
; Args:
;   rdi -- address of the string
; Return:
;   rax -- length of the string

strlen:
    xor al, al
    xor rcx, rcx
    not rcx
    cld
    repne scasb
    not rcx
    dec rcx
    mov rax, rcx
    ret

;-------------------------------------------
; endswith(*s1, *s2)
;   Test if s1 ends with s2, return 0 if true.
; Args:
;   rdi -- address of string 1
;   rsi -- address of string 2
; Return:
;   rax -- 0 if true, else 1

endswith:
    enter 24, 0
    mov [rbp-8], rdi
    mov [rbp-16], rsi
    call strlen
    mov [rbp-24], rax
    mov rdi, [rbp-16]
    call strlen
    mov rdx, rax
    mov rsi, [rbp-8]
    mov rdi, [rbp-16]
    add rsi, [rbp-24]
    sub rsi, rdx
    mov rcx, rdx

endswith_loop:
    mov al, [rsi]
    mov bl, [rdi]
    cmp al, bl
    jne endswith_neq
    inc rsi
    inc rdi
    loop endswith_loop
    mov rax, 0
    leave
    ret
    
endswith_neq:
    mov rax, 1
    leave
    ret

;-------------------------------------------
; strcmp(*s1, *s2)
;   Compare strings, return 0 if same.
; Args:
;   rdi -- address of string 1
;   rsi -- address of string 2
; Return:
;   rax -- 0 if same, else 1

strcmp:
    enter 24, 0
    mov [rbp-8], rdi
    mov [rbp-16], rsi
    call strlen
    mov [rbp-24], rax
    mov rdi, [rbp-16]
    call strlen
    cmp [rbp-24], rax
    jne strcmp_neq
    mov rdx, rax
    mov rsi, [rbp-8]
    mov rdi, [rbp-16]
    add rsi, [rbp-24]
    sub rsi, rdx
    mov rcx, rdx

strcmp_loop:
    mov al, [rsi]
    mov bl, [rdi]
    cmp al, bl
    jne strcmp_neq
    inc rsi
    inc rdi
    loop strcmp_loop
    mov rax, 0
    leave
    ret

strcmp_neq:
    mov rax, 1
    leave
    ret

;-------------------------------------------
; strncmp(*s1, *s2, n)
;   Compare n bytes of 2 strings, return 0 if same.
; Args:
;   rdi -- address of string 1
;   rsi -- address of string 2
;   rdx -- number of bytes to compare
; Return:
;   rax -- 0 if same, else 1

strncmp:
    mov rcx, rdx

strncmp_loop:
    mov al, [rsi]
    mov bl, [rdi]
    cmp al, bl
    jne strncmp_neq
    inc rsi
    inc rdi
    loop strncmp_loop
    mov rax, 0
    ret

strncmp_neq:
    mov rax, 1
    ret

;-------------------------------------------
; get_file_size(*name)
; Args:
;   rdi -- file name address
; Return:
;   rax -- file size

get_file_size:
    mov rax, 4              ; sys_stat  
    mov rsi, file_stat      ; stat strucure
    syscall
    mov rax, [file_stat+48] ; stat.st_size
    ret

;-------------------------------------------
; exit()
;   Exit 0.

exit:
    mov rdi, 0
    mov rax, 60
    syscall
