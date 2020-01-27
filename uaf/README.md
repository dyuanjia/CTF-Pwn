# UAF

## Description:

> Use after free.

> PS. Running on Ubuntu 16.04.

## Solution:

First step is information leak, to leak PIE base address. Since the message will be printed after the input, and `read()` do not need newline char or null terminator, 8 "a"s will fill the first 8 bytes in the data section, immediately after is the address of the `bye()` function, thus when printed, the address of `bye()` will be leaked. The PIE base address, and in turn, the address of `backdoor()`, can be calculated using offsets.

This calculated address can be used to overwrite the address of `bye()` in the second round. In the last round, simply malloc a chunk bigger than fast bin so that it does not interfere with the overwritten address.
