# ROP

## Description:

> Return to .plt

## Solution:

For this question, the plt entries in the binary contain the target function `system()`, and an input function `gets()`.

Using `gets()`, I can write any command into a writable memory, pop it into rdi, and call `system()`.
