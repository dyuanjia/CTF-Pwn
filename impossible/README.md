# Impossible

## Description:

> Happy New Year!

> Never trust user's input!

> I think it is impossible to bypass my checking :P

> 老皮上完計安，了解到 code 不能亂寫，於是在輸入前都寫了嚴格的檢查，具有駭客思維的你，是否依舊能把他的程式 pwn 下來呢 (๑•̀ㅂ•́)ﻭ✧

## Solution:

In C, `INT_MIN = -2147483648`. When passed into the `abs()` function, it becomes `2147483648`, which is bigger than `INT_MAX = 2147483647` (`int` is 32 bits). This results in overflow and the number wraps back to `-2147483648`. In addition, `ssize_t read(int fildes, void *buf, size_t nbytes)`'s third argument is an unsigned integer, i.e. `-2147483648` will be interpreted as a large positivei integer.

Since canary and PIE are off, this is allows buffer overflow with ROP chain.

`FLAG{H0w_did_y0u_byp4ss_my_ch3cking?_I7s_imp0ss1b1e!}`
