import numpy as np


class AES:
    def __init__(self):
        self.nb = 4  # number of coloumn of State (for AES = 4)
        self.nr = 10  # number of rounds ib ciper cycle (if nb = 4 nr = 10)
        self.nk = 4  # the key length (in 32-bit words)
        self.key = None
        self.open_bytes = None
        self.cipher_bytes = None
        # This dict will be used in SubBytes().
        self.hex_symbols_to_int = lambda str_num: int(str_num, 16)

        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

        self.inv_sbox = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]

        self.rcon = [[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        ]

    @staticmethod
    def prepare_state(input, n_const: int):
        state = []
        for i in range(4):
            state.append(input[i * n_const:(i + 1) * n_const])
        state = np.transpose(state).tolist()
        return state

    @staticmethod
    def prepare_output(state):
        state = np.transpose(state).tolist()
        output = []
        for r in range(4):
            output += state[r]
        return output

    def prepare_text(self, text):
        self.open_bytes = [ord(i) for i in list(text)]
        self.cipher_bytes = self.open_bytes[:]

    def encrypt(self):
        self.cipher_bytes = self.use_func(self.encrypt_for_part, self.open_bytes)
        return self.cipher_bytes

    def decrypt(self):
        self.open_bytes = self.use_func(self.decrypt_for_part, self.cipher_bytes)
        return self.open_bytes

    @staticmethod
    def use_func(func, before_func):
        num_of_blocks = len(before_func) // 16
        if len(before_func) % 16 != 0:
            num_of_blocks += 1
            before_func += [0] * (16 - len(before_func) % 16)
        after_func = []
        for i in range(1, num_of_blocks+1):
            block = before_func[(i - 1) * 16:i * 16]
            after_func += func(block)
        return after_func

    def encrypt_for_part(self, input_bytes):
        """Function encrypts the input_bytes according to AES(128) algorithm using the key
        Args:
           input_bytes -- list of int less than 255, ie list of bytes. Length of input_bytes is constantly 16
           key -- a string of plain text. Do not forget it! The same string is used in decryption
        Returns:
            List of int
        """
        if self.key is None:
            print("Key is None. Gen key first.")
            return None

        state = AES.prepare_state(input_bytes, self.nb)

        key_schedule = self.key_expansion()

        state = self.add_round_key(state, key_schedule)

        for rnd in range(1, self.nr):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, key_schedule, rnd)

        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, key_schedule, rnd + 1)

        output = AES.prepare_output(state, )

        return output

    def decrypt_for_part(self, cipher):
        """Function decrypts the cipher according to AES(128) algorithm using the key
        Args:
           cipher -- list of int less than 255, ie list of bytes
           key -- a strig of plain text. Do not forget it! The same string is used in decryption
        Returns:
            List of int
        """

        state = AES.prepare_state(cipher, self.nb)

        key_schedule = self.key_expansion()

        state = self.add_round_key(state, key_schedule, self.nr)

        rnd = self.nr - 1
        while rnd >= 1:
            state = self.shift_rows(state, inv=True)
            state = self.sub_bytes(state, inv=True)
            state = self.add_round_key(state, key_schedule, rnd)
            state = self.mix_columns(state, inv=True)

            rnd -= 1

        state = self.shift_rows(state, inv=True)
        state = self.sub_bytes(state, inv=True)
        state = self.add_round_key(state, key_schedule, rnd)

        output = AES.prepare_output(state)

        return output

    def sub_bytes(self, state, inv=False):
        """That transformation replace every element from State on element from Sbox
        according the algorithm: in hexadecimal notation an element from State
        consist of two values: 0x<val1><val2>. We take elem from crossing
        val1-row and val2-column in Sbox and put it instead of the element in State.
        If decryption-transformation is on (inv == True) it uses InvSbox instead Sbox.
        Args:
            inv -- If value == False means function is encryption-transformation.
                   True - decryption-transformation
        """

        if inv is False:  # encrypt
            box = self.sbox
        else:  # decrypt
            box = self.inv_sbox

        for i in range(len(state)):
            for j in range(len(state[i])):
                row = state[i][j] // 0x10
                col = state[i][j] % 0x10

                # Our Sbox is a flat array, not a bable. So, we use this trich to find elem:
                # And DO NOT change list sbox! if you want it working
                box_elem = box[16 * row + col]
                state[i][j] = box_elem

        return state

    @staticmethod
    def shift_list(shift_left: bool, input_list: list, pos_to_shift:int):
        sign = 2*shift_left - 1
        return input_list[sign*pos_to_shift:] + input_list[:sign*pos_to_shift]

    def shift_rows(self, state, inv=False):
        """That transformation shifts rows of State: the second rotate over 1 bytes,
        the third rotate over 2 bytes, the fourtg rotate over 3 bytes. The transformation doesn't
        touch the first row. When encrypting transformation uses left shift, in decription - right shift
        Args:
            inv: If value == False means function is encryption mode. True - decryption mode
        """

        shift_left = not inv
        for i in range(1, self.nb):
            state[i] = AES.shift_list(shift_left, state[i], i)

        return state

    def mix_columns(self, state, inv=False):
        """When encrypting transformation multiplyes every column of State with
        a fixed polinomial a(x) = {03}x**3 + {01}x**2 + {01}x + {02} in Galua field.
        When decrypting multiplies with a'(x) = {0b}x**3 + {0d}x**2 + {09}x + {0e}
        Detailed information in AES standart.
        Args:
            inv: If value == False means function is encryption mode. True - decryption mode
        """

        for i in range(self.nb):

            if inv == False:  # encryption
                s0 = AES.mul_by_02(state[0][i]) ^ AES.mul_by_03(state[1][i]) ^ state[2][i] ^ state[3][i]
                s1 = state[0][i] ^ AES.mul_by_02(state[1][i]) ^ AES.mul_by_03(state[2][i]) ^ state[3][i]
                s2 = state[0][i] ^ state[1][i] ^ AES.mul_by_02(state[2][i]) ^ AES.mul_by_03(state[3][i])
                s3 = AES.mul_by_03(state[0][i]) ^ state[1][i] ^ state[2][i] ^ AES.mul_by_02(state[3][i])
            else:  # decryption
                s0 = AES.mul_by_0e(state[0][i]) ^ AES.mul_by_0b(state[1][i]) ^ AES.mul_by_0d(state[2][i]) ^ AES.mul_by_09(state[3][i])
                s1 = AES.mul_by_09(state[0][i]) ^ AES.mul_by_0e(state[1][i]) ^ AES.mul_by_0b(state[2][i]) ^ AES.mul_by_0d(state[3][i])
                s2 = AES.mul_by_0d(state[0][i]) ^ AES.mul_by_09(state[1][i]) ^ AES.mul_by_0e(state[2][i]) ^ AES.mul_by_0b(state[3][i])
                s3 = AES.mul_by_0b(state[0][i]) ^ AES.mul_by_0d(state[1][i]) ^ AES.mul_by_09(state[2][i]) ^ AES.mul_by_0e(state[3][i])

            state[0][i] = s0
            state[1][i] = s1
            state[2][i] = s2
            state[3][i] = s3

        return state

    def get_key_symb_from_key(self):
        temp_key = str(self.key)
        temp_key = "0" * (3 - len(temp_key) % 3) if len(temp_key) % 3 != 0 else "" + temp_key
        key_symbols = [int(temp_key[(i-1)*3:i*3]) for i in range(1, len(temp_key)//3 + 1)]
        return key_symbols

    def key_expansion(self):
        """It makes list of RoundKeys for function AddRoundKey. All details
        about algorithm is is in AES standart
        """

        if self.key is None:
            print("Key is None. Gen key first.")
            return

        key_symbols = self.get_key_symb_from_key()

        # ChipherKey should contain 16 symbols to fill 4*4 table. If it's less
        # complement the key with "0x01"
        if len(key_symbols) < 4 * self.nk:
            key_symbols += [0x01] * (4*self.nk - len(key_symbols))

        # make ChipherKey(which is base of KeySchedule)

        key_schedule = AES.prepare_state(key_symbols, n_const=self.nk)

        # Comtinue to fill KeySchedule
        for col in range(self.nk, self.nb * (self.nr + 1)):  # col - column number
            if col % self.nk == 0:
                # take shifted (col - 1)th column...
                tmp = [key_schedule[row][col - 1] for row in range(1, 4)]
                tmp.append(key_schedule[0][col - 1])

                # change its elements using Sbox-table like in SubBytes...
                for j in range(len(tmp)):
                    sbox_row = tmp[j] // 0x10
                    sbox_col = tmp[j] % 0x10
                    sbox_elem = self.sbox[16 * sbox_row + sbox_col]
                    tmp[j] = sbox_elem

                # and finally make XOR of 3 columns
                for row in range(4):
                    s = (key_schedule[row][col - 4]) ^ (tmp[row]) ^ (self.rcon[row][int(col / self.nk - 1)])
                    key_schedule[row].append(s)

            else:
                # just make XOR of 2 columns
                for row in range(4):
                    s = key_schedule[row][col - 4] ^ key_schedule[row][col - 1]
                    key_schedule[row].append(s)

        return key_schedule

    def add_round_key(self, state, key_schedule, round=0):
        """That transformation combines State and KeySchedule together. Xor
        of State and RoundSchedule(part of KeySchedule).
        """

        for col in range(self.nk):
            # nb*round is a shift which indicates start of a part of the KeySchedule
            s0 = state[0][col] ^ key_schedule[0][self.nb * round + col]
            s1 = state[1][col] ^ key_schedule[1][self.nb * round + col]
            s2 = state[2][col] ^ key_schedule[2][self.nb * round + col]
            s3 = state[3][col] ^ key_schedule[3][self.nb * round + col]

            state[0][col] = s0
            state[1][col] = s1
            state[2][col] = s2
            state[3][col] = s3

        return state


    # Small helpful functions block
    @staticmethod
    def mul_by_02(num):
        """The function multiplies by 2 in Galua space"""

        if num < 0x80:
            res = (num << 1)
        else:
            res = (num << 1) ^ 0x1b

        return res % 0x100

    @staticmethod
    def mul_by_03(num):
        """The function multiplies by 3 in Galua space
        example: 0x03*num = (0x02 + 0x01)num = num*0x02 + num
        Addition in Galua field is oparetion XOR
        """
        return (AES.mul_by_02(num) ^ num)

    @staticmethod
    def mul_by_09(num):
        # return mul_by_03(num)^mul_by_03(num)^mul_by_03(num) - works wrong, I don't know why
        return AES.mul_by_02(AES.mul_by_02(AES.mul_by_02(num))) ^ num

    @staticmethod
    def mul_by_0b(num):
        # return mul_by_09(num)^mul_by_02(num)
        return AES.mul_by_02(AES.mul_by_02(AES.mul_by_02(num))) ^ AES.mul_by_02(num) ^ num

    @staticmethod
    def mul_by_0d(num):
        # return mul_by_0b(num)^mul_by_02(num)
        return AES.mul_by_02(AES.mul_by_02(AES.mul_by_02(num))) ^ AES.mul_by_02(AES.mul_by_02(num)) ^ num

    @staticmethod
    def mul_by_0e(num):
        # return mul_by_0d(num)^num
        return AES.mul_by_02(AES.mul_by_02(AES.mul_by_02(num))) ^ AES.mul_by_02(AES.mul_by_02(num)) ^ AES.mul_by_02(num)

# from Server import gen_aes_key
#
# if __name__ == "__main__":
#     aes = AES()
#     text_before = "hello my dear friend i'm glad to see you"
#     aes.key = gen_aes_key()
#     aes.prepare_text(text_before)
#     cipher_text = aes.encrypt()
#     print(f"cipher text = {cipher_text}")
#
#     open_text = aes.decrypt()
#     text_after = ''.join([chr(num) for num in open_text if num != 0])
#     print(f"open text = {text_after}")

