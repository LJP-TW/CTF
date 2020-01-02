;===========================================

section .data

response_header_part_1:
    db "HTTP/1.1 200 OK", 13, 10
    db "Server: Apache Lite 2.4.8", 13, 10
    db "Content-Length: ", 0

response_header_part_2:
    db 13, 10, "Content-Type: ", 0

response_header_part_3:
    db 13, 10, 13, 10, 0

error_response:
    db "HTTP/1.1 200 OK", 13, 10
    db "Server: Apache Lite 2.4.8", 13, 10
    db "Content-Length: 49", 13, 10
    db "Content-Type: text/html", 13, 10
    db 13, 10
    db "<h1>Error 404</h1>Woops! The page doesn't exist!", 10, 0

root_index_name:
    db "/"

index_name:
    db "index.html", 0

file_ext_html:
    db ".html", 0

file_ext_css:
    db ".css", 0

file_ext_js:
    db ".js", 0

content_type_plain:
    db "text/plain", 0

content_type_html:
    db "text/html", 0

content_type_js:
    db "text/javascript", 0

content_type_css:
    db "text/css", 0

req_GET:
    db "GET "

req_html:
    db "html"

;===========================================

section .bss

req_path:
    resb 128

file_fd:
    resq 1

;===========================================

section .text

;-------------------------------------------
; response()
;   Read request and response to sockfd.
; Return:
;   rax -- 0 if success, else 1

response:
    call read_req_path      ; read and find request path

    cmp rax, 0
    jne response_exception  ; if fail to read

    call make_default_index ; add index name for directory

    mov rdi, req_path
    call log_GET            ; log GET path

    call open_req_file      ; try to open requested file
    cmp eax, 0
    jl response_error       ; response error if fail

    call send_response

    mov rax, 0              ; return success
    ret

response_error:
    mov rdi, [sockfd]       
    mov rsi, error_response 
    call dputs              ; response error 404

    mov rax, 0              ; return success
    ret

response_exception:
    mov rax, 1              ; return error
    ret

;-------------------------------------------
; send_response()
;   Write response to socket.

send_response:
    mov rdi, [sockfd]
    mov rsi, response_header_part_1
    call dputs              ; send part 1

    mov rdi, req_path       ; skip /
    call get_file_size
    mov rdi, [sockfd]
    mov rsi, rax            ; file size
    call dputi              ; send content length

    mov rdi, [sockfd]
    mov rsi, response_header_part_2
    call dputs              ; send part 2

    call get_content_type
    mov rsi, rax            ; string of content type
    mov rdi, [sockfd]
    call dputs              ; send content type

    mov rdi, [sockfd]
    mov rsi, response_header_part_3
    call dputs              ; send part 3

    mov rdi, [sockfd]
    mov rsi, [file_fd]
    call dstream            ; send file
    ret

;-------------------------------------------
; read_req_path()
;   Read GET path to req_path.
; Return:
;   rax -- 0 if success, else 1

read_req_path:

    enter 1000, 0

read_req_path_start:

    mov rax, 0          ; sys_read
    mov rdi, [sockfd]   ; read from client
    lea rsi, [rbp-1000]   ; store in req_path
    mov rdx, 1024       ; read only 1 line (<=1 KB) ; Buffer overflow???
    syscall

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

read_req_path_exception:
    mov rax, 1          ; return error
    leave
    ret

;-------------------------------------------
; open_req_file()
;   Open the requested file, save it's fd in file_fd.

open_req_file:
    mov rax, 2          ; sys_open
    mov rdi, req_path   ; skip '/' <- root
    mov rsi, 0          ; O_RDONLY (read only)
    syscall
    mov [file_fd], rax  ; save file descriptor to file_fd
    ret

;-------------------------------------------
; make_default_index()
;   If the path ends with '/', append index name to it.

make_default_index:
    mov rdi, req_path
    call strlen
    lea rbx, [rax+req_path-1]
    mov al, '/'
    cmp al, [rbx]
    jne make_default_index_end

    inc rbx
    push rbx
    mov rdi, index_name
    call strlen
    mov rcx, rax
    mov rsi, index_name
    pop rdi
    rep movsb           ; append index name
    mov byte [rdi], 0

make_default_index_end:
    ret

;-------------------------------------------
; get_content_type()
;   Determine content type.
; Return:
;   rax -- address of type name

get_content_type:
    mov rdi, req_path
    mov rsi, file_ext_html
    call endswith
    cmp rax, 0
    je get_content_type_html

    mov rdi, req_path
    mov rsi, file_ext_css
    call endswith
    cmp rax, 0
    je get_content_type_css

    mov rdi, req_path
    mov rsi, file_ext_js
    call endswith
    cmp rax, 0
    je get_content_type_js

    mov rax, content_type_plain
    ret

get_content_type_html:
    mov rax, content_type_html
    ret

get_content_type_css:
    mov rax, content_type_css
    ret

get_content_type_js:
    mov rax, content_type_js
    ret
