import string


# nto{Wh0_54id_Th1s_1S_M3d1um} - correct
# nto{Wh0_54id_Th1s_1S_M3d!Um}
# nto{Wh0_54id_Th1s_1S_M3d!ul}
# nto{Wh0_54id_Th1s_1S_M3d!um}
# nto{Wh0_54id_Th1s_1S_M3d8Um}
# nto{Wh0_54id_Th1s_1S_M3d8ul}
# nto{Wh0_54id_Th1s_1S_M3d8um}

# b'nto{Wh0_54id_Th1s_1S_M3d0Qt}'
# b'nto{Wh0_54id_Th1s_1S_M3d0Qu}'
# b'nto{Wh0_54id_Th1s_1S_M3d1Pt}'
def trans(trmut):
    forg = '{otndcbahgfe1lki54329876}qp0'
    orig = 'nto{abcdefghikl1234567890pq}'

    res = [b' ' for _ in range(len(trmut))]
    for i in range(len(forg)):
        res[orig.index(forg[i])] = trmut[i]
    return bytes(res)


from z3 import *

t1, t2, t3, t4, t5, t6, t7 = [BitVec(f't{i}', 32) for i in range(1, 7 + 1)]

s = Solver()
s.add(t1 == 0x6e746f7b)

t1 &= 0x2C2C2C2C
s0 = 0x2c24 << 16
s0 = s0 | 0x2c28
s.add(s0 == t1)

t1 ^= t2
s0 = 0x7b4c << 16
s0 = s0 | 0x1c77
s.add(s0 == t1)

t1 ^= t3
s0 = 0x4e78 << 16
s0 = s0 | 0x7513
s.add(s0 == t1)

args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t4 & 0xff) == ord(l))
s.add(Or(*args))
args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t4 & 0xff00) >> 8 == ord(l))
s.add(Or(*args))
args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t4 & 0xff0000) >> 16 == ord(l))
s.add(Or(*args))

args = []
for l in string.ascii_letters + string.digits + '_':
    args.append((t4 & 0xff000000) >> 24 == ord(l))
s.add(Or(*args))

args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t7 & 0xff) == 125)
s.add(Or(*args))
args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t7 & 0xff00) >> 8 == ord(l))
s.add(Or(*args))
args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t7 & 0xff0000) >> 16 == ord(l))
s.add(Or(*args))

args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t7 & 0xff000000) >> 24 == ord(l))
s.add(Or(*args))

s.add(t4 == 1599367217)
t1 &= t4
s0 = 0x4e50 << 16
s0 |= 0x6011
s.add(s0 == t1)

t1 ^= t5
s0 = 0x3d0f << 16
s0 |= 0x5142
s.add(s0 == t1)

t1 ^= t6
s0 = 0x6242 << 16
s0 |= 0x6226
s.add(s0 == t1)

t1 &= t7
s0 = 0x2040 << 16
s0 |= 0x6024

s.add(s0 == t1)
# s.add(t4!=1599432793)
# s.add(t1==int.from_bytes(b'{otn', 'little'))
while True:
    s.check()
    m = s.model()
    # print(m)
    vr = sorted([(d, int(str(m[d])).to_bytes(4, 'little')) for d in m], key=lambda x: str(x[0]))
    # print(vr)
    s.add(t7 != int.from_bytes(vr[-1][1], 'little'))
    bbb = b''
    for v in vr:
        bbb += v[1]
    # print(bbb)
    print(trans(bbb))
