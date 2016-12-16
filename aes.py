import random
import sys

# Rijndael S-box
sbox =  [   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

# Rijndael Inverted S-box
inv_sbox = [   0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]

# Rijndael rcon
rcon = [    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
            0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
            0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
            0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
            0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
            0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
            0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
            0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
            0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
            0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
            0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
            0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
            0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
            0xe8, 0xcb ]

column_matrix = [
                [2, 1, 1, 3],
                [3, 2, 1, 1],
                [1, 3, 2, 1],
                [1, 1, 3, 2],
                ]

inv_column_matrix = [
                        [0xe, 0x9, 0xd, 0xb],
                        [0xb, 0xe, 0x9, 0xd],
                        [0xd, 0xb, 0xe, 0x9],
                        [0x9, 0xd, 0xb, 0xe],
                        ]

"""
State as an in_array. The in_array should be a Rijndael state
Key should be a 4*Nk where Nk is defined is respectably 4, 6, 8 for AES 128/192/256 
nb should be the standard number of blocks for this implementation
nr should be the number of rounds as defined by FIPS standards

"""
def cipher(in_array, key, nb = 4, nr = 10):
    state = in_array
    word_array = key_expansion(key, 4, nb, nr)
    state = add_round_key(state, [word_array[i] for i in range(4)])
    for i in range(1, nr):
        state = sub_bytes(state, nb, sbox)
        state = shift_rows(state, nb, 1)
        state = mix_columns(state, nb)
        state = add_round_key(state, [word_array[(i*nb)+j] for j in range(4)])
    state = sub_bytes(state, nb, sbox)
    state = shift_rows(state, nb, 1)
    state = add_round_key(state, [word_array[(nb*nr)+i] for i in range(4)])
    return state

def inv_cipher(in_array, key, nb = 4, nr = 10):
    state = in_array
    word_array = key_expansion(key, 4, nb, nr)
    state = add_round_key(state, [word_array[(nb*nr)+i] for i in range(4)])
    for i in range(nr-1, 0, -1):
        state = shift_rows(state, 4, -1)
        state = sub_bytes(state, 4, inv_column_matrix)
        state = add_round_key(state, [word_array[(i*nb)+j] for j in range(4)])
        state = inv_mix_columns(state, 4)
    state = shift_rows(state, 4, -1)
    state = sub_bytes(state, 4, inv_column_matrix)
    state = add_round_key(state, [word_array[i] for i in range(4)])
    return state



def add_round_key(state, word_array):
    for i in range(4):
        state[i] = add_round_key_helper(state[i], word_array[i])
    return state

def add_round_key_helper(column, word):
    for i in range(4):
        column[i] = column[i] ^ word[i]
    return column



def sub_bytes(state, num_blocks, table):
    for c in range(num_blocks):
        for r in range(4):
            state[r][c] = table[state[r][c]]
    return state


    
def shift_row(row, offset):
    idx = -offset % len(row)
    return row[idx:] + row[:idx]

def shift_rows(state, num_blocks, direction):
    for r in range(1, num_blocks):
        row = extract_row(state, num_blocks, r)
        row = shift_row(row, direction*r)
        state = insert_row(state, num_blocks, row, r)
    return state
def insert_row(state, num_blocks, replace, row):
    for i in range(num_blocks):
        state[i][row] = replace[i]
    return state

def extract_row(state, num_blocks, row):
    return [state[i][row] for i in range(num_blocks)]



def mix_columns(state, num_blocks):
    for r in range(num_blocks):
        state[r] = matrix_mult([state[r]], column_matrix, plusGF256, multGF256)[0]
    return state
def inv_mix_columns(state, num_blocks):
    for r in range(num_blocks):
        state[r] = matrix_mult([state[r]], inv_column_matrix, plusGF256, multGF256)[0]
    return state


def matrix_mult(B, A, plus, multi):
    if (len(B[0]) != len(A)):
        raise Exception ("Matrix Dimension Error")
        sys.exit(1)
    res = [[0 for i in range(len(A[0]))] for j in range(len(B))]
    for i in range(len(B)):
        for j in range(len(A[0])):
            for k in range(len(A)):
                res[i][j] = plus(res[i][j], multGF256(B[i][k], A[k][j]))
    return res



def plusGF256(A, B):
    return A ^ B

def multGF256(p, q):
    irpoly = 0x11b
    mask1 = 0x100
    r = 0
    while q:
        if q & 1:
            r ^= p
        p <<= 1
        if p & mask1:
            p ^= irpoly
        q >>= 1
    return r



def key_expansion(key, nk, nr = 10, nb = 4):
    word = []
    i = 0
    t_word = []
    while (i < nk):
        word += [[key[i][0], key[(i)][1], key[(i)][2], key[i][3]]]
        i += 1
    i = nk
    while (i < nb * (nr+1)):
        temp = word[i-1]
        if (i % nk == 0):
            temp = ls_xor(sub_word(rot_word(temp)), [rcon[i//nk], 0, 0, 0])
        elif(nk > 6 and i % nk == 4):
            temp = sub_word(temp)
        temp = ls_xor(word[i-nk], temp)
        word += [temp]
        i += 1
    return word


def print_array(arr):
    for i in arr:
        print(i)

def print_inverted_arr(arr):
    for i in arr:
        for j in i:
            print(invert_byte(j))


#takes a bytestring as input and yields bytes until empty. 
def sub_word(word):
    for i in range(len(word)):
        word[i] = sbox[word[i]]
    return word

def rot_word(word):
    word = word[1:] + [word[0]]
    return word



def ls_xor(word, temp):
    word = list(word)
    for i in range(len(word)):
        word[i] = word[i] ^ temp[i]
    return word



def invert_byte(byte):
    yield_byte = 0
    if (type(byte) == str):
        byte = ord(byte)
    for i in range(8):
        yield_byte = (yield_byte << 1) | (byte & 1)
        byte >>= 1
    return yield_byte



#yields each byte of the string
def process_string_input(process_string, invert):
    for c in process_string:
        print(c)
        c = ord(c)
        if (invert):
            c = invert_byte(c)
        yield c



#takes an input string and yields states until the string is fully processed
def pack_input(process_string, state_size = 4, invert=True):
    input_generator = process_string_input(process_string, invert)
    state = []
    current_input = []
    square_size = state_size * state_size
    curr_len = 0
    while True:
        try:
            current_input += [input_generator.next()]
            curr_len += 1
            #add rows of size state_size into state
            if (curr_len  % state_size == 0):
                state += [current_input]
                current_input = []
            #return a state of state_size * state_size 
            if (curr_len == square_size):
                yield state
                curr_len = 0
                current_input = []
                state = []
        except Exception as e:
            print (tr(e))
            break
    zero_ls = [0 for i in range(state_size)]
    current_input += [0 for i in range(state_size-(curr_len%state_size))]
    curr_len = curr_len - (curr_len % state_size)
    state += [current_input]
    added = state_size - (curr_len // state_size) - 1
    state += [zero_ls] * added
    print("Last State: " + str(state))
    if not(is_empty(state)):
        yield state
    
def unpack_state(state, state_size = 4, invert = False):
    ret = ''
    last = False
    if (ends(state)):
        print(state)
        last = True
    for r in range(state_size):
        for c in range(state_size):
            t = state[r][c]
            if (last and t == 0):
                continue
            t = invert_byte(t)
            ret += chr(t)
    return ret



def ends(state):
    flag = False
    ret = False
    for i in range(4):
        for j in range(4):
            if (state[i][j] == 0 and flag):
                # r = (i-1) % 4
                # c = (j-1) % 4
                ret = True
            elif (state[i][j] == 0):
                flag = True
            elif (flag):
                flag = False
                ret = False

    return ret

def is_empty(state):
    for i in state:
        for j in i:
            if (j != 0):
                return False
    return True

# main function 
def run_aes(filename, key, aes_func, nb = 4):
    output_file = str(input("What do you want to name the output file: "))
    input_data = read_in_file(filename)
    state_generator = pack_input(input_data, nb)
    output_writer = write_to_file(output_file)
    output_writer.send(None)
    while True:
        try:
            state = state_generator.next()
            modified = aes_func(state, key)
            unpacked = unpack_state(modified)
            output_writer.send(unpacked)
        except StopIteration:
            print("StopIteration")
            print(modified)
            break
        except Exception as e:
            print(str(e))
            # print "Run AES Except"
            break


def read_in_file(filename):
    full_input = ''
    f = open(filename, 'r')
    for line in f.readlines():
        full_input += line
    return full_input

def write_to_file(filename):
    f = open(filename, 'wb')
    while True:
        data = yield
        f.write(str(data))


#### Slack code
def bitstring_to_kbit_stream(n, num_words, k=8):
    """
    Convery a string of bits (an int) into a stream of kbit blocks
    """
    mask = (1<<k)-1
    for i in range(num_words):
        yield n&mask
        n >>= k


def convert_int(inp,num_blocks):
    """
    Convert a single int of num_blocks*4 bits into a Rijdael state
    """
    return [list(bitstring_to_kbit_stream(b,4,8))
        for b in bitstring_to_kbit_stream(inp,num_blocks,32)]


def pack_state(state,num_blocks):
    result = 0
    for r in range(num_blocks):
        for c in range(4):
            result <<= 8
            result |= state[-(r+1)][-(c+1)]
    return result

    
def state_to_str(state, num_blocks):
    """
    Convert a Rijndael state into a human readable
    string for debugging
    """
    s = ""
    for r in range(4):
        for c in range(num_blocks):
            s += "%02x "%state[r][c]
        s += "\n"
    for c in range(num_blocks):
        s += "%02x "%state[r][c]
    return s


if __name__ == "__main__":
    key = [[random.randint(0,255) for i in range(4)]for j in range(4)] 
    run_aes("test.txt", key, cipher)
    run_aes("test.enc", key, inv_cipher)
