# Note

## Description:

> Pwn the binary with full protection and without overflow.

> PS. Running on Ubuntu 16.04.

## Solution:

First, leak libc address with use after free.

Then, overwrite `__malloc_hook` with one gadget using double free.

To find one gadget:

```console
root@kali:~# one_gadget ./libc-2.23.so
```

Fitting the one gadget constraints may require some experimenting, e,g, different ways to trigger `malloc()`. In this case, when libc detects double free and triggers error, it will call `malloc()` in the process such that the constraint is satisfied.
