import pwn
import subprocess

def remote(host, port):
    r = pwn.remote(host, port)
    cmd = r.recvline_contains('hashcash -mb').decode().strip()
    hashcash_stamp = subprocess.check_output(cmd.split()).strip()
    r.sendlineafter('your hashcash stamp:', hashcash_stamp)
    r.recvuntil('check: ok\n')
    return r
