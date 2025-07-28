import sys

SHA3_256_RATE_BITS = 1088
SHA3_OUTPUT_LEN = 256
ROUND_NUM = 24

STATE = 1600
STATE_IN_BYTES = STATE // 8  # 200

LANE_SIZE_BITS = 64
LANE_SIZE_BYTES = LANE_SIZE_BITS // 8  # 8

MATRIX_DIM = 5

# Costanti di rotazione per rho
ROTATION_CONSTANTS = [
#   y=0 y=1 y=2 y=3 y=4
    [0, 36, 3, 41, 18],    # x=0
    [1, 44, 10, 45, 2],    # x=1
    [62, 6, 43, 15, 61],   # x=2
    [28, 55, 25, 21, 56],  # x=3
    [27, 20, 39, 8, 14]    # x=4
]

ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

def padding(message_bytes: bytes, rate_in_bits: int) -> bytes:
    rate_in_bytes = rate_in_bits // 8
    message_bytes += b'\x06'  # delimitatore per SHA-3

    zeros_to_add = rate_in_bytes - (len(message_bytes) % rate_in_bytes)

    if zeros_to_add == 0:
        zeros_to_add = rate_in_bytes

    message_bytes += b'\x00' * (zeros_to_add - 1)
    message_bytes += b'\x80'  # ultimo byte del padding

    return message_bytes

def divide_into_blocks(padded_bytes: bytes, rate_in_bits: int) -> list[bytes]:
    rate_in_bytes = rate_in_bits // 8
    blocks = []
    for i in range(0, len(padded_bytes), rate_in_bytes):
        block = padded_bytes[i:i + rate_in_bytes]
        blocks.append(block)
    return blocks

def pre_processing(message_bytes: bytes, rate_in_bits: int) -> list[bytes]:
    padded_message = padding(message_bytes, rate_in_bits)
    blocks = divide_into_blocks(padded_message, rate_in_bits)
    return blocks

def bytes_to_lanes(byte_data: bytearray) -> list[int]:
    lanes = []
    for i in range(0, STATE_IN_BYTES, LANE_SIZE_BYTES):
        lane = int.from_bytes(byte_data[i:i+LANE_SIZE_BYTES], 'little')
        lanes.append(lane)
    return lanes

def lanes_to_bytes(lanes: list[int]) -> bytearray:
    byte_data = bytearray()
    for lane in lanes:
        byte_data.extend(lane.to_bytes(LANE_SIZE_BYTES, 'little'))
    return byte_data

def ROL64(a, n):
    mask = 0xFFFFFFFFFFFFFFFF
    return ((a << n) | (a >> (LANE_SIZE_BITS - n))) & mask

def theta(A: list[list[int]]) -> list[list[int]]:
    C = []
    for x in range(MATRIX_DIM):
        column_parity = 0
        for y in range(MATRIX_DIM):
            column_parity ^= A[x][y]
        C.append(column_parity)
    D = []
    for x in range(MATRIX_DIM):
        D.append(C[(x - 1) % MATRIX_DIM] ^ ROL64(C[(x + 1) % MATRIX_DIM], 1))
    A_new = [[0]*MATRIX_DIM for _ in range(MATRIX_DIM)]
    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            A_new[x][y] = A[x][y] ^ D[x]
    return A_new

def rho(A: list[list[int]]) -> list[list[int]]:
    A_new = [[0]*MATRIX_DIM for _ in range(MATRIX_DIM)]
    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            A_new[x][y] = ROL64(A[x][y], ROTATION_CONSTANTS[x][y])
    return A_new

def pi(A: list[list[int]]) -> list[list[int]]:
    A_new = [[0]*MATRIX_DIM for _ in range(MATRIX_DIM)]
    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            A_new[x][y] = A[(x + 3*y) % MATRIX_DIM][x]
    return A_new

def chi(A: list[list[int]]) -> list[list[int]]:
    A_new = [[0]*MATRIX_DIM for _ in range(MATRIX_DIM)]
    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            A_new[x][y] = A[x][y] ^ ((A[(x+1)%MATRIX_DIM][y] ^ 0xFFFFFFFFFFFFFFFF) & A[(x+2)%MATRIX_DIM][y])
    return A_new

def iota(A: list[list[int]], round_index: int) -> list[list[int]]:
    A[0][0] ^= ROUND_CONSTANTS[round_index]
    return A

def keccak_f(state: bytearray) -> bytearray:
    lanes = bytes_to_lanes(state)
    # prepara la matrice 5x5
    A = [[0]*MATRIX_DIM for _ in range(MATRIX_DIM)]
    for x in range(MATRIX_DIM):
        for y in range(MATRIX_DIM):
            A[x][y] = lanes[x + MATRIX_DIM*y]

    # 24 round
    for round_index in range(ROUND_NUM):
        A = theta(A)
        A = rho(A)
        A = pi(A)
        A = chi(A)
        A = iota(A, round_index)

    # riconverte la matrice
    lanes_flat = []
    for y in range(MATRIX_DIM):
        for x in range(MATRIX_DIM):
            lanes_flat.append(A[x][y])

    return lanes_to_bytes(lanes_flat)

def absorbing(state: bytearray, blocks: list[bytes], rate_in_bytes: int) -> bytearray:
    for block in blocks:
        for i in range(rate_in_bytes):
            state[i] ^= block[i]
        state = keccak_f(state)
    return state

def squeezing(state: bytearray, rate_in_bytes: int, output_len_bits: int) -> bytes:
    output_len_bytes = output_len_bits // 8
    return bytes(state[:output_len_bytes])

def sponge_construction(blocks: list[bytes], rate_in_bits: int, output_len_bits: int) -> bytes:
    state = bytearray(STATE_IN_BYTES)
    rate_in_bytes = rate_in_bits // 8
    state = absorbing(state, blocks, rate_in_bytes)
    return squeezing(state, rate_in_bytes, output_len_bits)

def sha3_256(message: bytes) -> bytes:
    blocks = pre_processing(message, SHA3_256_RATE_BITS)
    return sponge_construction(blocks, SHA3_256_RATE_BITS, SHA3_OUTPUT_LEN)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <file>")
        return
    try:
        with open(sys.argv[1], 'rb') as input_file:
            message = input_file.read()
    except FileNotFoundError:
        print(f"Error: file not found '{sys.argv[1]}'")
        return
    hash_result = sha3_256(message)
    print(hash_result.hex())

if __name__ == '__main__':
    main()
