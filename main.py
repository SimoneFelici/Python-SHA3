import sys

SHA3_256_RATE_BITS = 1088

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
