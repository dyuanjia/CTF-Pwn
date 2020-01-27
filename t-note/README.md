# T-Note

## Description:

> TT

> PS. Running on Ubuntu 18.04.

## Solution:

Tcache is a new mechanism introduced after Ubuntu 17.10 to improve performance. It removed the checks for double free and whether the malloc size is legal. Also, in addition to fast bins, small bins will also be put into tcache instead of unsorted bin. Thus, need to malloc a bin with size bigger than small bin.

First, leak libc address with use after free.

Then, overwrite `__free_hook` with one gadget using double free.
