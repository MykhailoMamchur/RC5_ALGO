from math import sin

class MD5():
    def __init__(self):
        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476

        self.functions = 16*[lambda b, c, d: (b & c) | (~b & d)] + 16*[lambda b, c, d: (d & b) | (~d & c)] + 16*[lambda b, c, d: b ^ c ^ d] + 16*[lambda b, c, d: c ^ (b | ~d)]
        self.index_functions = 16*[lambda i: i] + 16*[lambda i: (5*i + 1) % 16] + 16*[lambda i: (3*i + 5) % 16] + 16*[lambda i: (7*i) % 16]
        self.constants = [int(abs(sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

        self.shift = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        ]


    def reset_state(self):
        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476


    def left_rotate(self, x, y):
        return ((x << (y & 31)) | ((x & 0xffffffff) >> (32 - (y & 31)))) & 0xffffffff


    def msg_prepare(self, msg, length=None):
        message = bytearray(msg)
        if length == None: orig_len_in_bits = (8 * len(message)) % (2 ** 64)
        else: orig_len_in_bits = (8 * length) % (2 ** 64)

        message.append(0x80)

        while len(message) % 64 != 56:
            message.append(0)
       
        message += orig_len_in_bits.to_bytes(8, byteorder='little')
        return message


    def get_digest(self):
        return b''.join(x.to_bytes(length=4, byteorder='little') for x in [self.A, self.B, self.C, self.D]).hex()


    def get_bytearray(self):
        a = bytearray()
        for x in [self.A, self.B, self.C, self.D]:
            a += x.to_bytes(length=4, byteorder='little')
        return a


    def hash(self, msg, auto_padding=True, overwrite=True, return_bytes=False):
        if (overwrite): self.reset_state()
        functions = self.functions
        index_functions = self.index_functions
        constants = self.constants

        if (auto_padding): message = self.msg_prepare(msg)
        else: message = msg

        for chunk_offset in range(0, len(message), 64):
            a, b, c, d = self.A, self.B, self.C, self.D
            chunk = message[chunk_offset : chunk_offset + 64]

            for i in range(64):
                f = functions[i](b, c, d)
                g = index_functions[i](i)
                to_rotate = a + f + constants[i] + int.from_bytes(chunk[4*g : 4*g+4], byteorder='little')
                a = (b + self.left_rotate(to_rotate, self.shift[i])) % (2 ** 32)
                a, b, c, d = d, a, b, c

            self.A = (self.A + a) % (2 ** 32)
            self.B = (self.B + b) % (2 ** 32)
            self.C = (self.C + c) % (2 ** 32)
            self.D = (self.D + d) % (2 ** 32)
        
        if return_bytes: return self.get_bytearray()
        else: return self.get_digest()
