;===========================================

section .data

log_listening_head:
    db "[*] Start listening on port ", 0

log_connect_text:
    db "[+] Connection established", 10, 0

log_disconnect_text:
    db "[+] Disconnected", 10, 0

log_start_text:
    db "Apache Lite 2.4.8", 10, 0

log_stop_text:
    db "[*] Stopping", 10, 0

log_message_head:
    db "[*] ", 0

log_GET_head:
    db "GET ", 0

;===========================================

section .text

log_start:
    mov rdi, log_start_text
    call puts
    ret

log_stop:
    mov rdi, log_stop_text
    call puts
    ret

log_connect:
    mov rdi, log_connect_text
    call puts
    ret

log_disconnect:
    mov rdi, log_disconnect_text
    call puts
    ret

log_listening:
    mov rdi, log_listening_head
    call puts
    mov rdi, [port]
    call puti
    mov rdi, endl
    call puts
    ret

log_message:
    push rdi            ; message address
    mov rdi, log_message_head
    call puts          ; print message head
    pop rdi
    call puts          ; print message
    mov rdi, endl
    call puts          ; print endl
    ret

log_GET:
    push rdi            ; path address
    mov rdi, log_GET_head
    call puts          ; print GET head
    pop rdi
    call puts          ; print path
    mov rdi, endl
    call puts          ; print endl
    ret
