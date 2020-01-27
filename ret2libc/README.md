# ret2libc

## Description:

> Libc is powerful.

## Solution:

There are no information leak vulnerability in the program itself. However, it can still be achieved through ROP chain. A libc address can be printed with `puts()`, and the base address can then be calculated. The function `__libc_start_main()`'s address is chosen to be leaked. This is because it is called before `main()`, thus its GOT entry is guaranteed to be resolved.

Next, calculate the target function's address with its offset, and jump back to the start of `main()` to extend program execution.

In this second round of buffer overflow, the target function `system()` can then be called.
