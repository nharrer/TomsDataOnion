import sys
import re
import math
from dataclasses import dataclass
# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad

FILE_LAYER0 = 'layer0.txt'
FILE_LAYER1 = 'layer1.txt'
FILE_LAYER2 = 'layer2.txt'
FILE_LAYER3 = 'layer3.txt'
FILE_LAYER4 = 'layer4.txt'
FILE_LAYER5 = 'layer5.txt'
FILE_LAYER6 = 'layer6.txt'
FILE_LAYER7 = 'layer7.txt'

# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------

def run():
    try:
        #test_base85()
        decode(FILE_LAYER0, FILE_LAYER1, decode_layer0)
        decode(FILE_LAYER1, FILE_LAYER2, decode_layer1)
        decode(FILE_LAYER2, FILE_LAYER3, decode_layer2)
        decode(FILE_LAYER3, FILE_LAYER4, decode_layer3)
        decode(FILE_LAYER4, FILE_LAYER5, decode_layer4)
        decode(FILE_LAYER5, FILE_LAYER6, decode_layer5)
        decode(FILE_LAYER6, FILE_LAYER7, decode_layer6)
        print('DONE!')
    except UserError as err:
        print('ERROR:', err)

def decode(infile, outfile, decoder):
    indata = readfile(infile)
    indata = from_base85adobe(indata)
    outdata = decoder(indata)
    writefile(outfile, outdata)
    print(f'{infile} decoded to {outfile}')

# -------------------------------------------------------------------------
# Base85 Encoder / Decoder
# -------------------------------------------------------------------------

def number_to_base85(num):
    str = ''
    for _ in range(5):
        str = chr(num % 85 + 33) + str
        num = num // 85
    return str

def to_base85(data):
    # todo move in blocks per 4
    ret = ''
    cnt = 0
    num = 0
    for c in data:
        num = num << 8
        num = num + ord(c)
        cnt = cnt + 1
        if cnt == 4:
            ret = ret + number_to_base85(num)
            cnt = 0
            num = 0

    if cnt > 0:
        # pad last unfinished block with zeroes
        extra = 4 - cnt
        num = num << (8 * extra)
        ret = ret + number_to_base85(num)
        ret = ret[:-extra]

    return ret

def base85_to_number(block):
    n = 0
    for c in block:
        n = n * 85
        n = n + ord(c) - 33

    bytes = bytearray()
    for _ in range(4):
        c = n & 0xff
        n = n >> 8
        bytes.insert(0, c)

    return bytes

def from_base85(data):
    idx = 0
    len_data = len(data)
    ret = bytearray()
    while(idx < len_data):
        block = data[idx:idx+5]
        cut = 0
        while len(block) < 5:
            block = block + 'u'
            cut = cut + 1
        ret = ret + base85_to_number(block)[:4-cut]
        idx = idx + 5

    return ret

def from_base85adobe(data):
    # cut text within delimiters <~ ~>
    try:
        start = data.index('<~')
    except ValueError:
        raise UserError(
            'The start delimiter <~ is missing in adobe base85 encoded string.')

    d = data[start + 2:]

    try:
        end = d.index('~>')
    except ValueError:
        raise UserError(
            'The end delimiter ~> is missing in adobe base85 encoded string.')

    d = d[:end]

    # remove all whitespaces
    d = "".join(d.split())

    return from_base85(d)

def test_base85():
    test = '01234567890'
    for x in range(1, len(test) + 1):
        d1 = test[:x]
        d2 = to_base85(d1)
        d3 = from_base85(d2).decode('ascii')
        print(d1 + ' -> ' + d2)
        print(d3)
        if d1 != d3:
            raise UserError('Base85 decode error!')

# -------------------------------------------------------------------------
# Tools
# -------------------------------------------------------------------------

class UserError(Exception):
    def __init__(self, message):
        self.message = message

def readfile(filename):
    with open(filename, 'r') as file:
        return file.read()


def writefile(filename, bytes):
    with open(filename, "wb") as file:
        file.write(bytes)

def bytearray_to_wordlist(bytes, bytes_per_word=1):
    ret = []
    word = 0
    cnt = 0
    for b in bytes:
        word = word << 8
        word = word | b
        cnt = cnt + 1
        if cnt == bytes_per_word:
            ret.append(word)
            cnt = 0
            word = 0
    # pad if there is an unfinished last word
    if cnt > 0:
        word = word << 8 * (bytes_per_word - cnt)
        ret.append(word)

    return ret

def word_to_bytearray(word, bytes_per_word=1):
    return word.to_bytes(bytes_per_word, 'big')

def wordlist_to_bytearray(words, bytes_per_word=1):
    buffer = bytearray()
    for word in words:
        buffer = buffer + word_to_bytearray(word, bytes_per_word)
    return buffer

def dump_wordlist(words, bytes_per_word=1, wrap_after_bytes=None):
    if wrap_after_bytes == None:
        wrap_after_bytes = len(words) * bytes_per_word
    step = wrap_after_bytes // bytes_per_word
    while len(words) > 0:
        words1 = words[:step]
        words = words[step:]
        for num in words1:
            s = hex(num)[2:]
            s = s.zfill(bytes_per_word * 2)
            s = s.upper()
            print(s + ' ', end='')
        print()

def dump16(data: bytearray):
    dumphex(data, 2, 32)

def dumphex(data: bytearray, bytes_per_word=2, wrap_after_bytes=None):
    words = bytearray_to_wordlist(data, bytes_per_word)
    dump_wordlist(words, bytes_per_word, wrap_after_bytes)

# -------------------------------------------------------------------------
# Layer 0
# -------------------------------------------------------------------------

def decode_layer0(data):
    return data

# -------------------------------------------------------------------------
# Layer 1
# -------------------------------------------------------------------------

def decode_layer1(data):
    out = bytearray()
    for c in data:
        c = c ^ 0b01010101
        c = (c >> 1) | ((c % 2) << 7)
        out.append(c)
    return out

# -------------------------------------------------------------------------
# Layer 2
# -------------------------------------------------------------------------

def decode_layer2(data):
    out = bytearray()
    pos = 1
    byte = 0
    for c in data:
        if check_parity(c):
            pos = (pos - 1) % 8
            c = c & 0b11111110
            if pos == 0:
                byte = c
                continue

            add = c >> pos
            byte = byte | add
            out.append(byte)

            byte = (c << (8 - pos)) & 0b11111111

    return out


def check_parity(c):
    p = 0
    for _ in range(8):
        p = p ^ c
        c = c >> 1
    return (p & 1) == 0

# -------------------------------------------------------------------------
# Layer 3
# -------------------------------------------------------------------------

def decode_layer3(data):
    key = bytearray('==[ Layer 4/6: Network Traffic ]', 'ascii')
    for idx in range(32):
        key[idx] = key[idx] ^ data[idx]

    out = bytearray()
    idx = 0
    for c in data:
        out.append(c ^ key[idx])
        idx = (idx + 1) % len(key)

    return out

# -------------------------------------------------------------------------
# Layer 4
# -------------------------------------------------------------------------

def decode_layer4(data):
    packets = decode_ipv4(data)
    packets_filtered = filter_ipv4(packets)

    #dump_packets('packets1.txt', packets)
    #dump_packets('packets2.txt', packets_filtered)

    out = bytearray()
    for p in packets_filtered:
        out = out + p.udp.data
    return out

def decode_ipv4(data):
    packets = []
    idx = 1
    while len(data) > 0:
        packet = IPv4(data, idx)
        packets.append(packet)
        data = data[packet.length:]
        idx = idx + 1

    return packets

def filter_ipv4(packets):
    source = IPAddress(10, 1, 1, 10)
    dest = IPAddress(10, 1, 1, 200)
    return list(filter(lambda p: p.src_ip == source and p.dst_ip == dest and p.checksum_ok and p.udp.checksum_ok and p.udp.dst_port == 42069, packets))

def checksum(data: bytearray, skipidx=-1):
    sum = 0
    for idx in range(math.ceil(len(data) / 2)):
        idx1 = idx * 2
        idx2 = idx1 + 1
        if skipidx != idx1:
            d1 = data[idx1]
            if idx2 >= len(data):
                d2 = 0
            else:
                d2 = data[idx2]
            word = d1 << 8 | d2
            sum = sum + word
    while sum > 0xffff:
        sum = (sum & 0xffff) + (sum >> 16)

    return sum ^ 0xffff

def dump_packets(filename, packets):
    out = bytearray()
    for p in packets:
        out = out + bytearray(str(p) + '\n', 'ascii')
    writefile(filename, out)

# nicer string representation of our dataclasses
def auto_str(cls):
    def __str__(self):
        vrs = vars(self).items()
        vrs = map(lambda v: (v[0], str(v[1]).zfill(10)) if v[0] == 'checksum' or v[0] == 'checksum_calc' or v[0]
                  == 'idx' or v[0] == 'length' or v[0] == 'src_port' or v[0] == 'dst_port' else v, vrs)
        vrs = map(lambda v: (v[0], 'True ') if v[1] == True else v, vrs)
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join('%s=%s' % item for item in vrs)
        )
    cls.__str__ = __str__
    return cls

@dataclass
class IPAddress:
    b1: int
    b2: int
    b3: int
    b4: int

    def __str__(self):
        return f'{self.b1}.{self.b2}.{self.b3}.{self.b4}'.rjust(15)

    def data(self):
        return bytearray([self.b1, self.b2, self.b3, self.b4])

@auto_str
@dataclass
class UDP:
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    checksum: int = 0
    checksum_calc: int = 0
    checksum_ok: bool = False
    data: bytearray = bytearray()

    def __init__(self, data: bytearray, idx: int, src_ip: IPAddress, dst_ip: IPAddress, protocol: int):
        if len(data) < 8:
            return

        self.src_port = (data[0] << 8) | data[1]
        self.dst_port = (data[2] << 8) | data[3]
        self.length = (data[4] << 8) | data[5]
        self.checksum = (data[6] << 8) | data[7]
        self.checksum_calc = 0
        self.checksum_ok = False
        self.data = data[4 * 2:self.length]

        udp_length = len(data)

        psyeudoheader = src_ip.data() + dst_ip.data() + bytearray([0, protocol, udp_length >> 8, udp_length & 0xff])
        data_checksum = psyeudoheader + data

        self.checksum_calc = checksum(data_checksum, len(psyeudoheader) + 6)
        if self.checksum_calc == 0:
            self.checksum_calc = 0xffff
        self.checksum_ok = self.checksum == self.checksum_calc

@auto_str
@dataclass
class IPv4:
    idx: int
    version: int
    ihl: int
    dscp: int
    ecn: int
    length: int
    identification: int
    flags: int
    frag_offset: int
    ttl: int
    protocol: int
    checksum: int
    checksum_calc: int
    checksum_ok: bool
    src_ip: IPAddress
    dst_ip: IPAddress
    udp: bytearray

    def __init__(self, data: bytearray, idx: int):
        self.idx = idx

        b1 = data[0]
        self.version = b1 >> 4
        self.ihl = b1 & 0b1111

        b2 = data[1]
        self.dscp = b2 >> 2
        self.ecn = b2 & 0b11

        self.length = (data[2] << 8) | data[3]
        self.identification = (data[4] << 8) | data[5]

        b3 = (data[6] << 8) | data[7]
        self.flags = b3 >> (16 - 3)
        self.frag_offset = b3 & 0b1111111111111

        self.ttl = data[8]
        self.protocol = data[9]
        self.checksum = (data[10] << 8) | data[11]
        self.checksum_calc = checksum(data[:self.ihl * 4], 10)
        self.checksum_ok = self.checksum == self.checksum_calc

        self.src_ip = IPAddress(data[12], data[13], data[14], data[15])
        self.dst_ip = IPAddress(data[16], data[17], data[18], data[19])

        self.udp = UDP(data[self.ihl * 4:self.length], idx, self.src_ip, self.dst_ip, self.protocol)

# -------------------------------------------------------------------------
# Layer 5
# -------------------------------------------------------------------------

def decode_layer5(data):
    pos_kek = 0
    pos_iv1 = pos_kek + 32
    pos_key = pos_iv1 + 8
    pos_iv2 = pos_key + 40
    pos_data = pos_iv2 + 16

    kek = data[pos_kek:pos_kek+32]
    iv1 = data[pos_iv1:pos_iv1+8]
    key_encrypted = data[pos_key:pos_key+40]
    iv2 = data[pos_iv2:pos_iv2+16]
    data_encrypted = data[pos_data:]

    key = unwrap(key_encrypted, kek, iv1)
    counter = Counter.new(128, initial_value=int.from_bytes(iv2, byteorder='big'), little_endian=False)
    cipher = AES.new(key, mode=AES.MODE_CTR, counter=counter)
    cleartext = cipher.decrypt(pad(data_encrypted, AES.block_size))

    return cleartext[:len(data_encrypted)]

# shamelessly stolen from https://github.com/tomdalling/aes_key_wrap/blob/master/lib/aes_key_wrap.rb
# see also: https://tools.ietf.org/html/rfc3394
def unwrap(wrapped_key, kek, iv=word_to_bytearray(0xA6A6A6A6A6A6A6A6, 8)):
    buffer = bytearray_to_wordlist(wrapped_key, 8)
    block_count = len(buffer) - 1
    cipher = AES.new(kek, AES.MODE_ECB)
    for j in range(5, -1, -1):
        for i in range(block_count, 0, -1):
            round = block_count*j + i
            buffer[0] = buffer[0] ^ round

            data = wordlist_to_bytearray([buffer[0],  buffer[i]], 8)
            data2 = cipher.decrypt(data)
            [buffer[0], buffer[i]] = bytearray_to_wordlist(data2, 8)

    if word_to_bytearray(buffer[0], 8) != iv:
        raise UserError('IV does not match unwrapped key.')

    return wordlist_to_bytearray(buffer[1:], 8)

# -------------------------------------------------------------------------
# Layer 6
# -------------------------------------------------------------------------

def decode_layer6(data):
    # "hello world" example:
    #data = bytearray([0x50, 0x48, 0xC2, 0x02, 0xA8, 0x4D, 0x00, 0x00, 0x00, 0x4F, 0x02, 0x50, 0x09, 0xC4, 0x02, 0x02, 0xE1, 0x01, 0x4F, 0x02, 0xC1, 0x22, 0x1D, 0x00, 0x00, 0x00, 0x48, 0x30, 0x02, 0x58, 0x03, 0x4F, 0x02, 0xB0, 0x29, 0x00, 0x00, 0x00, 0x48, 0x31, 0x02, 0x50, 0x0C, 0xC3, 0x02, 0xAA, 0x57, 0x48, 0x02, 0xC1, 0x21, 0x3A, 0x00, 0x00, 0x00, 0x48, 0x32, 0x02, 0x48, 0x77, 0x02, 0x48, 0x6F, 0x02, 0x48, 0x72, 0x02, 0x48, 0x6C, 0x02, 0x48, 0x64, 0x02, 0x48, 0x21, 0x02, 0x01, 0x65, 0x6F, 0x33, 0x34, 0x2C])
    machine = TomtelCore_i69(data)
    machine.run()
    return machine.output

class TomtelCore_i69:
    mem: bytearray
    output: bytearray
    opcodes: map

    a: int = 0
    b: int = 0
    c: int = 0
    d: int = 0
    e: int = 0
    f: int = 0

    la: int = 0
    lb: int = 0
    lc: int = 0
    ld: int = 0
    ptr: int = 0
    pc: int = 0

    def __init__(self, data: bytearray):
        self.mem = data
        self.output = bytearray()
        self.opcodes = {
            0xc2: self.add,
            0xe1: self.aptr,
            0xc1: self.cmp,
            0x21: self.jez,
            0x22: self.jnz,
            0x02: self.out,
            0xc3: self.sub,
            0xc4: self.xor,
        }

    def run(self):
        while True:
            self.checkaddr(self.pc, 'pc')
            opcode = self.mem[self.pc]
            if opcode == 0x01: #halt
                return
            if (opcode & 0b11000000) == 0b01000000:
                self.mv(opcode)
            elif (opcode & 0b11000000) == 0b10000000:
                self.mv32(opcode)
            elif opcode in self.opcodes:
                func = self.opcodes[opcode]
                func()
            else:
                raise UserError(f'Invalid opcode 0x{opcode:02x} at pc = 0x{self.pc:04x}')

    def checkaddr(self, addr, which):
        if addr >= len(self.mem):
            raise UserError(f'Addr out of range: {which} = 0x{addr:04x}, last memory address = 0x{len(self.mem)-1:04x}')

    def read(self, addr):
        self.checkaddr(addr, 'addr')
        return self.mem[addr]

    def write(self, addr, value):
        self.checkaddr(addr, 'addr')
        self.mem[addr] = value

    def read32(self, addr):
        v = self.read(addr + 0)
        v = v | (self.read(addr + 1) << 8)
        v = v | (self.read(addr + 2) << 16)
        v = v | (self.read(addr + 3) << 24)
        return v

    def readregister(self, reg):
        if reg < 1 or reg > 7:
            raise UserError(f'Invalid 8-bit register = {reg}')
        if reg == 1:
            return self.a
        if reg == 2:
            return self.b
        if reg == 3:
            return self.c
        if reg == 4:
            return self.d
        if reg == 5:
            return self.e
        if reg == 6:
            return self.f

        addr = self.ptr + self.c
        value = self.read(addr)
        return value

    def setregister(self, reg, value):
        if reg < 1 or reg > 7:
            raise UserError(f'Invalid 8-bit register = {reg}')
        elif reg == 1:
            self.a = value
        elif reg == 2:
            self.b = value
        elif reg == 3:
            self.c = value
        elif reg == 4:
            self.d = value
        elif reg == 5:
            self.e = value
        elif reg == 6:
            self.f = value
        else:
            addr = self.ptr + self.c
            self.write(addr, value)

    def readregister32(self, reg):
        if reg < 1 or reg > 6:
            raise UserError(f'Invalid 32-bit register = {reg}')
        if reg == 1:
            return self.la
        if reg == 2:
            return self.lb
        if reg == 3:
            return self.lc
        if reg == 4:
            return self.ld
        if reg == 5:
            return self.ptr
        if reg == 6:
            return self.pc

    def setregister32(self, reg, value):
        if reg < 1 or reg > 6:
            raise UserError(f'Invalid 32-bit register = {reg}')
        elif reg == 1:
            self.la = value
        elif reg == 2:
            self.lb = value
        elif reg == 3:
            self.lc = value
        elif reg == 4:
            self.ld = value
        elif reg == 5:
            self.ptr = value
        else:
            self.pc = value

    def add(self): # ADD a <- b
        self.pc = self.pc + 1
        self.a = (self.a + self.b)
        if self.a > 255:
            self.a = self.a % 256

    def aptr(self): # APTR imm8
        self.pc = self.pc + 2
        value = self.read(self.pc - 1)
        self.ptr = self.ptr + value

    def cmp(self): # CMP
        self.pc = self.pc + 1
        if self.a == self.b:
            self.f = 0
        else:
            self.f = 1

    def jez(self): # JEZ imm32
        addr = self.read32(self.pc + 1)
        if self.f == 0:
            self.pc = addr
        else:
            self.pc = self.pc + 5

    def jnz(self): # JNZ imm32
        addr = self.read32(self.pc + 1)
        if self.f != 0:
            self.pc = addr
        else:
            self.pc = self.pc + 5

    def mv(self, opcode):
        self.pc = self.pc + 1
        d = (opcode >> 3) & 0b111
        s = opcode & 0b111
        if s == 0:
            value = self.read(self.pc)
            self.pc = self.pc + 1
        else:
            value = self.readregister(s)
        self.setregister(d, value)

    def mv32(self, opcode):
        self.pc = self.pc + 1
        d = (opcode >> 3) & 0b111
        s = opcode & 0b111
        if s == 0:
            value = self.read32(self.pc)
            self.pc = self.pc + 4
        else:
            value = self.readregister32(s)
        self.setregister32(d, value)

    def out(self): # OUT a
        self.pc = self.pc + 1
        self.output.append(self.a)

    def sub(self): # SUB a <- b
        self.pc = self.pc + 1
        self.a = self.a - self.b
        if self.a < 0:
            self.a = self.a + 255

    def xor(self): # XOR a <- b
        self.pc = self.pc + 1
        self.a = self.a ^ self.b

# -------------------------------------------------------------------------
# DO IT
# -------------------------------------------------------------------------

if __name__ == '__main__':
    run()
