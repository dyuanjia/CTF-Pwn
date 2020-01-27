# EDU 2019 election

## Description:

> Who will win!!!

> Try to hack my voting system :D

> Ps. Running on ubuntu 18.04.

## Solution:

Since the bianry has full protection, the first step is to leak some information. To vote, you need to register with a token first. It has size 0xb8. During login, you need to enter the token again. However the size of the buffer to contain the input this time has size 0xc8. This means that you can enter a token with a larger size. Looking at the stack in gdb, canary is right after the first token buffer. Since `memcmp()` compares the content of first and second buffer using the second buffer's size, I can brute force the canary by trying the 7 bytes of canary one by one: if the output contains "Invalid token." it means that byte is wrong, so I simply increment the byte by 1 and try again.

Then, I noticed that the 6 bytes after the canary is the address of `__libc_csu_init()`. So I brute forced that as well using the same method.

The next step is stack overflow. This can be done using the msg buffer in `voting()`. The number of bytes read by `read()` depends on the candidate's votes. So, I increased Trump's votes to 255, because vote is an `uint8_t` which has a maximum value of 255. Given the layout on the stack: 224 (size of msg) + 8 + 8 (canary) + 8 (saved rbp) + 6 (return address), the overflow is just enough to overwrite the return address. There wouldn't be any space left for a ROP chain. However, on the stack immediately after is 0x10 bytes of junk, followed by the token buffer which I can control. I just need a ROP gadget to pop the junk off and the rsp will reach the token buffer.

I used the last 2 pops from `__libc_csu_init()` to pop off the 0x10 bytes of junk, and the return address will be at the start of the token buffer (ROP chain). This ROP chain will be used to leak the libc address. It will first return to `[pop rdi, ret]`, which will pop the address of `puts@got` (containing the value of the libc address of puts) into rdi, and then return to `puts@plt`. This will call puts and print out the libc address of puts. Using this, I can calculate the libc base address. Finally it will return to main after puts is finished, which allows me to construct another ROP chain to spawn a shell.

Using the same method of voting for 255 times and sending the message which will replace the return address to `[pop r14, pop r15, ret]`, I pop off the 0x10 bytes of junk on the stack again, and reach my second ROP chain. This time it will simply pop the address of "/bin/sh" into rdi, and then return to the address of system. This will call system("/bin/sh") and spawn a shell.

Since the binary has a time limit, and it takes some time to do the brute forcing and voting, I ran my exploit 3 times before I got the flag. This happens when the brute forcing part took relatively less time, which depends on the random values of the canary and `__libc_csu_init()` address.

`FLAG\{Wh0_h4cked_my_v0t1ng_sys7em_:P}`
