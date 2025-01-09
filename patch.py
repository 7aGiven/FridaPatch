import random
import string
import struct
import sys
    
with open(sys.argv[1], "rb") as f:
    exe = bytearray(f.read())

# dump frida-agent-<arch>.so
elfPattern = bytearray(b"\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03") # e_type = ET_DYN
def agent(EI_CLASS):
    elfPattern[4] = EI_CLASS
    tmpPos = -1
    n = 0
    while True:
        tmpPos = exe.find(elfPattern, tmpPos+1)
        if tmpPos == -1:
            break
        # e_entry == 0
        if struct.unpack_from("I", exe, tmpPos+0x18)[0] == 0:
            n += 1
            pos = tmpPos
    if n == 0:
        raise "not found frida-agent-%d.so in exe" % 32 * EI_CLASS
    if n > 1:
        raise "found %d frida-agent-%d.so in exe" % (n, 32 * EI_CLASS)
    if EI_CLASS == 2:
        eh = struct.unpack_from("<QQQIHHHHHH", exe, pos + 0x18)
    elif EI_CLASS == 1:
        eh = struct.unpack_from("<IIIIHHHHHH", exe, pos + 0x18)
    e_shoff = eh[2]; e_shentsize = eh[7]; e_shnum = eh[8]
    size = e_shoff + e_shentsize * e_shnum
    print("found frida-agent-%d.so in exe at 0x%X, size = 0x%X" % (32 * EI_CLASS, pos, size))
    return pos, bytearray(exe[pos : pos + size])
    
    

# EI_CLASS = ELFCLASS32
agent32Pos, agent32 = agent(1)
# EI_CLASS = ELFCLASS64
agent64Pos, agent64 = agent(2)

with open("frida-agent-origin-32.so", "wb") as f:
    f.write(agent32)
with open("frida-agent-origin-64.so", "wb") as f:
    f.write(agent64)

bit = False

def callback(f):
    global bit
    bit = "32"
    f(agent32)
    bit = "64"
    f(agent64)

strMap = {}
def rand(b, index, s):
    if s in strMap:
        randstr = strMap[s]
    else:
        while True:
            randstr = "".join(random.choices(string.ascii_letters, k=len(s)))
            if randstr != s:
                strMap[s] = randstr
                break
    b[index:index+len(s)] = randstr.encode()
    return randstr

def randUnique(b, s):
    pattern = b"\x00"+s.encode()+b"\x00"
    pos = b.find(pattern)
    if pos == -1:
        raise "not found %s" % s
    if b.find(pattern, pos+1) != -1:
        raise "%s not unique" % s
    print("replace unique str %s to %s in frida-agent-%s.so" % (s, rand(b, pos+1, s), bit))

def gmain(b):
    randUnique(b, "gmain")

callback(gmain)



with open("frida-agent-32.so", "wb") as f:
    f.write(agent32)
with open("frida-agent-64.so", "wb") as f:
    f.write(agent64)
exe[agent32Pos:agent32Pos+len(agent32)] = agent32
exe[agent64Pos:agent64Pos+len(agent64)] = agent64
with open("frida-server-patch", "wb") as f:
    f.write(exe)
