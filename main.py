import sys

SHA3_256_RATE_BITS = 1088
SHA3_OUTPUT_LEN = 256

# def bytes_to_bit_string(byte_data: bytes) -> str:
#     return ''.join(format(byte, '08b') for byte in byte_data)

# applica il padding (il messaggio deve essere divisibile per "r")
def padding(message_bytes: bytes, rate_in_bits: int) -> bytes:
    rate_in_bytes = rate_in_bits // 8
    message_bytes += b'\x06' # delimitatore per SHA-3 (00000110)
    
    zeros_to_add = rate_in_bytes - (len(message_bytes) % rate_in_bytes)
    
    # se è già multiplo di rate, aggiungi un altro blocco
    if zeros_to_add == 0:
        zeros_to_add = rate_in_bytes
        
    message_bytes += b'\x00' * (zeros_to_add - 1)
    message_bytes += b'\x80' # ultimo byte del padding (10000000)
    
    return message_bytes

# divide una sequenza di byte paddata in una lista di blocchi.
def divide_into_blocks(padded_bytes: bytes, rate_in_bits: int) -> list[bytes]:
    rate_in_bytes = rate_in_bits // 8
    blocks = []
    for i in range(0, len(padded_bytes), rate_in_bytes):
        start = i
        end = i + rate_in_bytes
        block = padded_bytes[start:end]
        blocks.append(block)
    return blocks

# esegue padding e divisione in blocchi.
def pre_processing(message_bytes: bytes, rate_in_bits: int) -> list[bytes]:
    padded_message = padding(message_bytes, rate_in_bits)
    blocks = divide_into_blocks(padded_message, rate_in_bits)
    return blocks

# converte una sequenza di byte in una lista di "lane" a 64 bit
def bytes_to_lanes(byte_data: bytearray) -> list[int]:
    lanes = []
    for i in range(0, 200, 8):
        lane = int.from_bytes(byte_data[i:i+8], 'little')
        lanes.append(lane)
    return lanes

# converte una lista di "lane" a 64 bit in una sequenza di byte
def lanes_to_bytes(lanes: list[int]) -> bytearray:
    byte_data = bytearray()
    for lane in lanes:
        byte_data.extend(lane.to_bytes(8, 'little'))
    return byte_data

def ROL64(a, n):
    mask = 0xFFFFFFFFFFFFFFFF
    return ((a << n) | (a >> (64 - n))) & mask

# theta round fuction
def theta(A: list[list[int]]) -> list[list[int]]:
    C = []
    for x in range(5):
        column_parity = A[0][x] ^ A[1][x] ^ A[2][x] ^ A[3][x] ^ A[4][x]
        C.append(column_parity)
        
    D = []
    for x in range(5):
        prev_column_parity = C[(x - 1) % 5]
        next_column_parity_rotated = ROL64(C[(x + 1) % 5], 1)
        D.append(prev_column_parity ^ next_column_parity_rotated)
    # Applica il risultato allo stato A
    A_new = [[0]*5 for _ in range(5)]
    for y in range(5):
        for x in range(5):
            A_new[y][x] = A[y][x] ^ D[x]
            
    return A_new

# funzione di permutazione principale
def keccak_f(state: bytearray) -> bytearray:
    # Converte i byte in una lista di 25 "lane"
    lanes = bytes_to_lanes(state)
    A = []
    for i in range(5):
        row = []
        for j in range(5):
            index = i * 5 + j
            row.append(lanes[index])
        A.append(row)

    # inizio dei 24 round di SHA-3
    for round_index in range(24):
        A = theta(A)
        # A = rho(A)
        # A = pi(A)
        # A = chi(A)
        # A = iota(A, round_index)

    # Riconverte la matrice 5x5 in una lista singola
    lanes_flat = []
    for i in range(5):
        for j in range(5):
            lanes_flat.append(A[i][j])

    # Riconverte la lista di lane in byte
    return lanes_to_bytes(lanes_flat)

# processa i blocchi del messaggio
def absorbing(state: bytearray, blocks: list[bytes], rate_in_bytes: int) -> None:
    for block in blocks:
        for i in range(rate_in_bytes):
            state[i] ^= block[i]
        state = keccak_f(state)

# estrae l'hash finale dallo stato
def squeezing(state: bytearray, rate_in_bytes: int, output_len_bits: int) -> bytes:
    output_len_bytes = output_len_bits // 8
    rate_part = state[:rate_in_bytes]
    final_hash = rate_part[:output_len_bytes]
    return bytes(final_hash)

# l'intera costruzione a spugna
def sponge_construction(blocks: list[bytes], rate_in_bits: int, output_len_bits: int) -> bytes:
    # lo stato è di 1600 bit = 200 byte
    state = bytearray(200)
    rate_in_bytes = rate_in_bits // 8
    absorbing(state, blocks, rate_in_bytes)
    final_hash = squeezing(state, rate_in_bytes, output_len_bits)
    return final_hash

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <file>")
        return
    try:
        with open(sys.argv[1], 'rb') as input_file:
            message = input_file.read()
    except FileNotFoundError:
        print(f"Errore: file non trovato '{sys.argv[1]}'")
        return
    
    blocks = pre_processing(message, SHA3_256_RATE_BITS)
    final_hash = sponge_construction(blocks, SHA3_256_RATE_BITS, SHA3_OUTPUT_LEN)
    print(final_hash.hex())

    # print(f"Messaggio diviso in {len(blocks)} blocchi.")
    # Itera sui blocchi e stampali in esadecimale e in binario
    # for i, block in enumerate(blocks):
    #     print("-" * 40)
    #     print(f"Blocco {i} ({len(block)} bytes):")
    #     print(f"  Hex: {block.hex()}")
    #     # Traduci il blocco in una stringa di bit
    #     bit_string = bytes_to_bit_string(block)
    #     print(f"  Bit ({len(bit_string)} bit):")
    #     print(f"    {bit_string}")

if __name__ == '__main__':
    main()
