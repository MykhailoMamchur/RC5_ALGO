import md5
import randomizer
from time import time

def lshift(val, r_bits, max_bits):
    v1 = (val << r_bits % max_bits) & (2 ** max_bits - 1)
    v2 = ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))
    return v1 | v2


def rshift(val, r_bits, max_bits):
    v1 = ((val & (2 ** max_bits - 1)) >> r_bits % max_bits)
    v2 = (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))
    return v1 | v2


class RC5(object):
    def __init__(self):
        self.w = 16
        self.r = 8
        self.b = 32
        self.P = 0xB7E1
        self.Q = 0x9E37
        self.randGenerator = randomizer.RandGenerator()
        self.blocksize = self.w*2
        

    def set_key(self, key):
        self._key = key


    def key_expand(self, key):
        w = self.w
        r = self.r
        b = self.b
        P, Q = self.P, self.Q

        u = w // 8
        c = b // u

        #L
        L = [0] * c
        for i in range(self.b - 1, -1, -1):
            L[i // (w // 8)] = (L[i // (w // 8)] << 8) + key[i]

        #S
        S = [P]
        t = 2 * (r + 1)
        for i in range(1, t):
            S.append((S[i - 1] + Q) % 2 ** w)

        #mix
        с = len(L)
        t = 2 * (r + 1)
        m = max(с, t)
        A = B = i = j = 0

        for _ in range(3 * m):
            A = S[i] = lshift(S[i] + A + B, 3, w)
            B = L[j] = lshift(L[j] + A + B, A + B, w)

            i = (i + 1) % t
            j = (j + 1) % с

        return S


    def block_encrypt(self, data, expanded_key):
        w = self.w
        r = self.r
        mod = 2 ** w

        A = int.from_bytes(data[:(self.w*2 // 8) // 2], byteorder='little')
        B = int.from_bytes(data[(self.w*2 // 8) // 2:], byteorder='little')

        A = (A + expanded_key[0]) % mod
        B = (B + expanded_key[1]) % mod

        for i in range(1, r + 1):
            A = (lshift((A ^ B), B, w) + expanded_key[2 * i]) % mod
            B = (lshift((A ^ B), A, w) + expanded_key[2 * i + 1]) % mod

        res = A.to_bytes((self.w*2 // 8) // 2, byteorder='little') + B.to_bytes((self.w*2 // 8) // 2, byteorder='little')
        return res


    def block_decrypt(self, data, expanded_key):
        w = self.w
        r = self.r
        mod = 2 ** w

        A = int.from_bytes(data[:(self.w*2 // 8) // 2], byteorder='little')
        B = int.from_bytes(data[(self.w*2 // 8) // 2:], byteorder='little')

        for i in range(r, 0, -1):
            B = rshift(B - expanded_key[2 * i + 1], A, w) ^ A
            A = rshift((A - expanded_key[2 * i]), B, w) ^ B

        B = (B - expanded_key[1]) % mod
        A = (A - expanded_key[0]) % mod

        res = A.to_bytes((self.w*2 // 8) // 2, byteorder='little') + B.to_bytes((self.w*2 // 8) // 2, byteorder='little')
        return res


    def encrypt_file(self, path_in, path_out):
        file_in = open(path_in, 'rb')
        file_out = open(path_out, 'wb')
        chunksize = self.w*2 // 8
        
        last_v = self.randGenerator.next().to_bytes(length=(chunksize), byteorder='little')
        expanded_key = self.key_expand(self._key)
        
        file_out.write(self.block_encrypt(last_v, expanded_key))        

        chunk = file_in.read(chunksize)
        pad_len = 0
        while chunk:
            pad_len = chunksize - len(chunk)
            for _ in range(pad_len): chunk += int.to_bytes(pad_len, length=1, byteorder='little')
            chunk = bytes([a ^ b for a, b in zip(last_v, chunk)])

            encrypted_chunk = self.block_encrypt(chunk, expanded_key)
            file_out.write(encrypted_chunk)
            last_v = encrypted_chunk

            chunk = file_in.read(chunksize)

        if pad_len == 0:
            pad_len = chunksize
            for _ in range(pad_len): chunk += int.to_bytes(pad_len, length=1, byteorder='little')
            chunk = bytes([a ^ b for a, b in zip(last_v, chunk)])
            encrypted_chunk = self.block_encrypt(chunk, expanded_key)
            file_out.write(encrypted_chunk)

        file_in.close()
        file_out.close()


    def decrypt_file(self, path_in, path_out):
        file_in = open(path_in, 'rb')
        file_out = open(path_out, 'wb')
        chunksize = self.blocksize // 8

        expanded_key = self.key_expand(self._key)
        last_v = self.block_decrypt(file_in.read(chunksize), expanded_key)

        chunk = file_in.read(chunksize)
        while chunk:
            decrypted_chunk = self.block_decrypt(chunk, expanded_key)
            decrypted_chunk = bytes([a ^ b for a, b in zip(last_v, decrypted_chunk)])
            last_v = chunk

            chunk = file_in.read(chunksize)
            if not chunk: decrypted_chunk = decrypted_chunk.rstrip(bytes([bytearray(decrypted_chunk)[-1]]))

            file_out.write(decrypted_chunk)

        file_in.close()
        file_out.close()

    

action = 9999
rc5 = RC5()
while action != '2':
    action = input("\nSelect needed action:\n0 - Ecrypt file\n1 - Decrypt file\n2 - Exit\n> ")
    if action == '0':
        print("Enter the input file path:")
        file_in = input()
        print("Enter the output (encrypted) file path:")
        file_out = input()
        print("Enter the key:")
        key = input()

        try: f = open(file_in, 'rb')
        except: 
            print('Error! File does not exist.')
            exit()

        hash = md5.MD5().hash(bytearray(key.encode(encoding='utf-8')), return_bytes=True)
        double_hash = md5.MD5().hash(bytearray(hash), return_bytes=True)

        rc5.set_key(hash + double_hash)
        timer = time()
        rc5.encrypt_file(file_in, file_out)
        print('Operation is successful.')
        print(f'Operation took {time() - timer} seconds')

    elif action == '1':
        print("Enter the input (encrypted) file path:")
        file_in = input()
        print("Enter the output file path:")
        file_out = input()
        print("Enter the key:")
        key = input()

        try: f = open(file_in, 'rb')
        except: 
            print('Error! File does not exist.')
            exit()

        hash = md5.MD5().hash(key.encode(encoding='utf-8'), return_bytes=True)
        double_hash = md5.MD5().hash(bytearray(hash), return_bytes=True)

        rc5.set_key(hash + double_hash)
        timer = time()
        rc5.decrypt_file(file_in, file_out)
        print('Operation is successful.')
        print(f'Operation took {time() - timer} seconds')