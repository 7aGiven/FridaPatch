import random
import string
import struct
    
with open("out/bin/frida-server","rb") as f:
    exe = bytearray(f.read())

# dump frida-agent-<arch>.so
def agent(EI_CLASS):
    # e_type = ET_DYN
    pattern = bytearray(b"\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03")
    pattern[4] = EI_CLASS
    pos = -1
    while True:
        pos = exe.find(pattern, pos+1)
        if pos == -1:
            return False
        # e_entry == 0
        if struct.unpack_from("I", exe, pos+0x18)[0] == 0:
            if EI_CLASS == 2:
                eh = struct.unpack_from("<QQQIHHHHHH", exe, pos + 0x18)
            elif EI_CLASS == 1:
                eh = struct.unpack_from("<IIIIHHHHHH", exe, pos + 0x18)
            e_shoff = eh[2]; e_shentsize = eh[7]; e_shnum = eh[8]
            return pos, bytearray(exe[pos : pos + e_shoff + e_shentsize * e_shnum])
    
    

# EI_CLASS = ELFCLASS32
agent32Pos, agent32 = agent(1)
# EI_CLASS = ELFCLASS64
agent64Pos, agent64 = agent(2)

with open("frida-agent-origin-32.so", "wb") as f:
    f.write(agent32)
with open("frida-agent-origin-64.so", "wb") as f:
    f.write(agent64)



def rand(b, index, s):
    while True:
        randstr = "".join(random.choices(string.ascii_letters, k=len(s)))
        if randstr != s:
            break
    print(b[index:index+len(s)])
    b[index:index+len(s)] = randstr.encode()
    print(b[index:index+len(s)])

def gmain(b):
    rand(b, b.index(b"\x00gmain\x00")+1, "gmain")
gmain(agent32)
gmain(agent64)



with open("frida-agent-32.so", "wb") as f:
    f.write(agent32)
with open("frida-agent-64.so", "wb") as f:
    f.write(agent64)
exe[agent32Pos:agent32Pos+len(agent32)] = agent32
exe[agent64Pos:agent64Pos+len(agent64)] = agent64
with open("frida-server", "wb") as f:
    f.write(exe)
