# Note++

## Description:

> Can you pwn it again with security patch?

> I think there is no vulnerability :P

> Ps. Running on ubuntu 16.04.

## Solution:

The Note struct consists of 3 attributes: is_freed, \*data, and description. Before freeing a chunk in the delete function, it will check is_freed. If it's 1, it means that its already been freed once, and this is supposed to prevent double free. However, is_freed only takes 1 bit, and is at the front of the Note struct. This can be overwritten with 0 using off-by-one with description: when scanf finish reading all 48 bytes of input, it will append a null byte at the end. Therefore, double free can still be achieved.

First, I added chunk0. An overlapping chunk will start in the middle of chunk0's data later on, so I initialized its data with the correct offset (0x40) and size header (0x71). Then, I added 3 chunks and freed them. The fast bin now look like this:

```
    fastbin --> chunk1 --> chunk2 --> chunk3 --> 0x0
```

Next, I added back chunk1 with off-by-one null byte in description. Chunk2's is_freed will be overwritten as zero, and its data can be printed out using `list()`. Since it's fd is pointing to chunk3, chunk3's address is leaked.

Then, I double freed chunk2, and immediately added it back with its data as the address of the overlapping chunk prepared in chunk0. The fast bin now look like this:

```
    fastbin --> chunk1 --> chunk2 --> overlapping chunk
```

Next, I added 3 chunks back. The last one (chunk4) is the overlapping chunk in the middle of chunk0's data, and before chunk1. Therefore, I can rewrite chunk1's header (size) to be 0xe1. The size of 0xe1 also allows its next chunk to be a valid chunk ($$0x70 * 2 = 0xe0$$), and will help avoid the `double free or corruption (!prev)` error when freeing it.

Now, when freeing chunk1, which has size 0xe0, it will be put into unsorted bin with fd and bk pointing to libc address. Using the same off-by-one trick, I can overwrite chunk1's is_freed to be 0, and leak the libc address with `list()`.

Then, still using the same off-by-one trick, I created another double free situation, with the last chunk in the linked list pointing to the address in front of the `__malloc_hook`. The fast bin now looks like this:

```
    fastbin --> chunk0 --> chunk1 --> __malloc_hook
```

After adding 2 chunks, I added another chunk with data as the address of an one gadget. The next time `malloc()` is called, the one gadget will be called instead. Finally, by freeing chunk4 (the one in the unsorted bin), an error will be triggered. However in the process, `malloc()` is called with the one gadget's required constraints, thus spawning a shell.

`FLAG\{Heap_exp1oit4ti0n_15_fun}`
