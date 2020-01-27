# re-alloc

## Description:

> RE-Alloc

## Solution:

UAF vulnerability in `reallocate()`, i.e. we can assign `size = 0` to free a memory.

Use `realloc(buf, 0)` to free `buf` and `realloc(buf, size_buf-0x20)` to get overlapped chunk.

Compiler will optimize `realloc(NULL, size)` to `malloc(size)`, which is useful as we can GOT hijack `realloc()` and `malloc()` will still be available.

GOT hijack `realloc()` to `puts()`. We can then leak arbitrary memory using `rfree()`, which will clean out the address to `NULL` and we can allocate another `buf` again.

Finally, GOT hijack `realloc()` to `system()` to get shell.

`FLAG{Heeeeeeeeeeeeeeeeeeeeeee4p}`
