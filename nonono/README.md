# nonono

## Description:

> Noooooooo0o0o0o0o0o0o0o000o

## Solution:

This is a menu question.

There is a index out-of-bound vulnerability, i.e. `note[-7]` can be used to overwrite memory, and leak code base address. However, only `stdin@@GLIBC_2.2.5`, `stdout@@GLIBC_2.2.5`, and `completed` can be overwritten.

Overwriting `stdout` can be used to fake `FILE` structure and get arbitrary leak. One requirement when faking `FILE` structure is an valid `lock` pointer. This can be bypassed with the function which prints the fake flag, which will free an valid `FILE` structure back into the heap.

Overwriting `stdin` can be used to achieve arbitrary write.

The tcache implemented in the libc version used is an outdated one, thus I only need to change `__free_hook` to system, and free a chunk containing a `/bin/sh` string to get shell.

`FLAG{Now_You_Know_the_File_Stream}`
