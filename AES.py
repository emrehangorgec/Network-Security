# AES implementation
import math
import random

# AES S-box
s_box = (
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
)

# AES inverse S-box
inv_s_box = (
    0x52,
    0x09,
    0x6A,
    0xD5,
    0x30,
    0x36,
    0xA5,
    0x38,
    0xBF,
    0x40,
    0xA3,
    0x9E,
    0x81,
    0xF3,
    0xD7,
    0xFB,
    0x7C,
    0xE3,
    0x39,
    0x82,
    0x9B,
    0x2F,
    0xFF,
    0x87,
    0x34,
    0x8E,
    0x43,
    0x44,
    0xC4,
    0xDE,
    0xE9,
    0xCB,
    0x54,
    0x7B,
    0x94,
    0x32,
    0xA6,
    0xC2,
    0x23,
    0x3D,
    0xEE,
    0x4C,
    0x95,
    0x0B,
    0x42,
    0xFA,
    0xC3,
    0x4E,
    0x08,
    0x2E,
    0xA1,
    0x66,
    0x28,
    0xD9,
    0x24,
    0xB2,
    0x76,
    0x5B,
    0xA2,
    0x49,
    0x6D,
    0x8B,
    0xD1,
    0x25,
    0x72,
    0xF8,
    0xF6,
    0x64,
    0x86,
    0x68,
    0x98,
    0x16,
    0xD4,
    0xA4,
    0x5C,
    0xCC,
    0x5D,
    0x65,
    0xB6,
    0x92,
    0x6C,
    0x70,
    0x48,
    0x50,
    0xFD,
    0xED,
    0xB9,
    0xDA,
    0x5E,
    0x15,
    0x46,
    0x57,
    0xA7,
    0x8D,
    0x9D,
    0x84,
    0x90,
    0xD8,
    0xAB,
    0x00,
    0x8C,
    0xBC,
    0xD3,
    0x0A,
    0xF7,
    0xE4,
    0x58,
    0x05,
    0xB8,
    0xB3,
    0x45,
    0x06,
    0xD0,
    0x2C,
    0x1E,
    0x8F,
    0xCA,
    0x3F,
    0x0F,
    0x02,
    0xC1,
    0xAF,
    0xBD,
    0x03,
    0x01,
    0x13,
    0x8A,
    0x6B,
    0x3A,
    0x91,
    0x11,
    0x41,
    0x4F,
    0x67,
    0xDC,
    0xEA,
    0x97,
    0xF2,
    0xCF,
    0xCE,
    0xF0,
    0xB4,
    0xE6,
    0x73,
    0x96,
    0xAC,
    0x74,
    0x22,
    0xE7,
    0xAD,
    0x35,
    0x85,
    0xE2,
    0xF9,
    0x37,
    0xE8,
    0x1C,
    0x75,
    0xDF,
    0x6E,
    0x47,
    0xF1,
    0x1A,
    0x71,
    0x1D,
    0x29,
    0xC5,
    0x89,
    0x6F,
    0xB7,
    0x62,
    0x0E,
    0xAA,
    0x18,
    0xBE,
    0x1B,
    0xFC,
    0x56,
    0x3E,
    0x4B,
    0xC6,
    0xD2,
    0x79,
    0x20,
    0x9A,
    0xDB,
    0xC0,
    0xFE,
    0x78,
    0xCD,
    0x5A,
    0xF4,
    0x1F,
    0xDD,
    0xA8,
    0x33,
    0x88,
    0x07,
    0xC7,
    0x31,
    0xB1,
    0x12,
    0x10,
    0x59,
    0x27,
    0x80,
    0xEC,
    0x5F,
    0x60,
    0x51,
    0x7F,
    0xA9,
    0x19,
    0xB5,
    0x4A,
    0x0D,
    0x2D,
    0xE5,
    0x7A,
    0x9F,
    0x93,
    0xC9,
    0x9C,
    0xEF,
    0xA0,
    0xE0,
    0x3B,
    0x4D,
    0xAE,
    0x2A,
    0xF5,
    0xB0,
    0xC8,
    0xEB,
    0xBB,
    0x3C,
    0x83,
    0x53,
    0x99,
    0x61,
    0x17,
    0x2B,
    0x04,
    0x7E,
    0xBA,
    0x77,
    0xD6,
    0x26,
    0xE1,
    0x69,
    0x14,
    0x63,
    0x55,
    0x21,
    0x0C,
    0x7D,
)


# Rijndael's key schedule rotate operation
def rotate(word):
    return word[1:] + word[:1]


# Rijndael's key schedule core operation
def key_schedule_core(word, iteration):

    # Rijndael's round constants
    rcon = (
        0x01,
        0x02,
        0x04,
        0x08,
        0x10,
        0x20,
        0x40,
        0x80,
        0x1B,
        0x36,
        0x6C,
        0xD8,
        0xAB,
        0x4D,
        0x9A,
        0x2F,
        0x5E,
        0xBC,
        0x63,
        0xC6,
        0x97,
        0x35,
        0x6A,
        0xD4,
        0xB3,
        0x7D,
        0xFA,
        0xEF,
        0xC5,
        0x91,
        0x39,
        0x72,
        0xE4,
        0xD3,
        0xBD,
        0x61,
        0xC2,
        0x9F,
        0x25,
        0x4A,
        0x94,
        0x33,
        0x66,
        0xCC,
        0x83,
        0x1D,
        0x3A,
        0x74,
        0xE8,
        0xCB,
    )

    # Rotate the input word
    word = rotate(word)
    # Apply S-box to all bytes of the word
    for i in range(4):
        word[i] = s_box[word[i]]
    # XOR the output of the rcon operation with the first byte
    word[0] = word[0] ^ rcon[iteration]
    return word

def multiply(x, y):
    """
    Multiply two numbers in the GF(2^8) finite field defined
    by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
    """
    result = 0
    for i in range(8):
        if y & 1:
            result ^= x
        carry = x & 0x80
        x <<= 1
        if carry:
            x ^= 0x1b
        y >>= 1
    return result & 0xFF

# Key expansion function
def expand_key(key, size, expanded_key_size):
    # Set the iteration count
    current_size = 0
    rcon_iteration = 1
    expanded_key = [0] * expanded_key_size

    # Initialize the expanded key with the input key
    for i in range(size):
        expanded_key[i] = key[i]
    current_size += size

    while current_size < expanded_key_size:
        # Assign the previous 4 bytes to the temporary value t
        t = expanded_key[current_size - 4 : current_size]

        # Every 16 bytes apply the core schedule to t
        if current_size % 16 == 0:
            t = key_schedule_core(t, rcon_iteration)
            rcon_iteration += 1

        # XOR t with the 4-byte block [16 bytes] before the new expanded key
        for i in range(4):
            expanded_key[current_size] = expanded_key[current_size - 16] ^ t[i]
            current_size += 1

    return expanded_key


# SubBytes step in AES
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = s_box[state[i][j]]


# Inverse SubBytes step in AES
def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_s_box[state[i][j]]


# ShiftRows step in AES
def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = (
        state[1][1],
        state[1][2],
        state[1][3],
        state[1][0],
    )
    state[2][0], state[2][1], state[2][2], state[2][3] = (
        state[2][2],
        state[2][3],
        state[2][0],
        state[2][1],
    )
    state[3][0], state[3][1], state[3][2], state[3][3] = (
        state[3][3],
        state[3][0],
        state[3][1],
        state[3][2],
    )


# Inverse ShiftRows step in AES
def inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = (
        state[1][3],
        state[1][0],
        state[1][1],
        state[1][2],
    )
    state[2][0], state[2][1], state[2][2], state[2][3] = (
        state[2][2],
        state[2][3],
        state[2][0],
        state[2][1],
    )
    state[3][0], state[3][1], state[3][2], state[3][3] = (
        state[3][1],
        state[3][2],
        state[3][3],
        state[3][0],
    )


# MixColumns step in AES
def mix_columns(state):
    for i in range(4):
        a = state[i][0]
        b = state[i][1]
        c = state[i][2]
        d = state[i][3]

        state[i][0] = multiply(a, 2) ^ multiply(b, 3) ^ c ^ d
        state[i][1] = a ^ multiply(b, 2) ^ multiply(c, 3) ^ d
        state[i][2] = a ^ b ^ multiply(c, 2) ^ multiply(d, 3)
        state[i][3] = multiply(a, 3) ^ b ^ c ^ multiply(d, 2)


# Inverse MixColumns step in AES
def inv_mix_columns(state):
    for i in range(4):
        a = state[i][0]
        b = state[i][1]
        c = state[i][2]
        d = state[i][3]

        state[i][0] = (
            multiply(a, 14) ^ multiply(b, 11) ^ multiply(c, 13) ^ multiply(d, 9)
        )
        state[i][1] = (
            multiply(a, 9) ^ multiply(b, 14) ^ multiply(c, 11) ^ multiply(d, 13)
        )
        state[i][2] = (
            multiply(a, 13) ^ multiply(b, 9) ^ multiply(c, 14) ^ multiply(d, 11)
        )
        state[i][3] = (
            multiply(a, 11) ^ multiply(b, 13) ^ multiply(c, 9) ^ multiply(d, 14)
        )


# AddRoundKey step in AES
def add_round_key(state, key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]


# AES encryption function
def aes_encrypt(plaintext, key):
    state = [list(plaintext[i : i + 4]) for i in range(0, len(plaintext), 4)]

    expanded_key = expand_key(key, len(key), 176)

    add_round_key(state, [expanded_key[i : i + 4] for i in range(0, 16)])

    for i in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, [expanded_key[i * 16 : i * 16 + 4] for i in range(4)])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(
        state,
        [
            expanded_key[160:164],
            expanded_key[164:168],
            expanded_key[168:172],
            expanded_key[172:176],
        ],
    )

    return [item for sublist in state for item in sublist]


# AES decryption function
def aes_decrypt(ciphertext, key):
    state = [list(ciphertext[i : i + 4]) for i in range(0, len(ciphertext), 4)]

    expanded_key = expand_key(key, len(key), 176)

    add_round_key(
        state,
        [
            expanded_key[160:164],
            expanded_key[164:168],
            expanded_key[168:172],
            expanded_key[172:176],
        ],
    )

    for i in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, [expanded_key[i * 16 : i * 16 + 4] for i in range(4)])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, [expanded_key[i : i + 4] for i in range(0, 16)])

    return [item for sublist in state for item in sublist]

def pad_pkcs7(data):
    padding_len = 16 - (len(data) % 16)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad_pkcs7(data):
    padding_len = data[-1]
    return data[:-padding_len]

def main():
    # Take plaintext and key input from the user
    plaintext_input = input("Enter the plaintext: ")
    key_input = input("Enter the key (16 characters): ")

    # Convert the input strings to byte arrays
    plaintext = bytes(plaintext_input, 'utf-8')
    key = bytes(key_input, 'utf-8')

    # Check if the key length is valid
    if len(key) != 16:
        print("Error: The key must be 16 characters long.")
        return

    # Pad the plaintext to a multiple of 16 bytes
    padded_plaintext = pad_pkcs7(plaintext)

    # Encrypt the plaintext
    encrypted = aes_encrypt(list(padded_plaintext), list(key))
    print("Encrypted:", encrypted)

    # Decrypt the ciphertext
    decrypted = aes_decrypt(encrypted, list(key))
    decrypted_text = bytes(unpad_pkcs7(decrypted))

    # Convert the decrypted bytes back to a string
    print("Decrypted text:", decrypted_text.decode('utf-8'))

if __name__ == "__main__":
    main()



