# Implementation of the RSA and AES
import math
import random

import AES as aes


# Function to check whether the given number is prime or not.
def is_prime(number):
    if number < 2:
        return False
    for i in range(2, int(number**0.5) + 1):
        if number % i == 0:
            return False
    return True


# Function to create a random integer between the given interval
def randint(min_value, max_value):
    return random.randint(min_value, max_value)


# Function to generate random prime numbers between the given interval
def generate_prime(min_value, max_value):
    prime = randint(min_value, max_value)
    while not is_prime(prime):
        prime = randint(min_value, max_value)
    return prime


# Find the "d" value which is equivalent to the e x d = 1 mod(totient_n)
def mod_inverse(e, totient_n):
    d = 3
    while (d * e) % totient_n != 1:
        d += 1
    return d


# ---------------------------------------------------------------------------
# --------Definiton of the functions to be used for Digital Signature--------
def split_into_blocks(message, block_size):
    # Splits the message into blocks of size 'block_size'.
    return [message[i : i + block_size] for i in range(0, len(message), block_size)]


def encrypt_block(block, d, n):
    # Encrypts a single block using RSA encryption: ciphertext = plaintext^e mod n.
    block_int = int.from_bytes(block.encode("utf-8"), byteorder="big")
    encrypted_block_int = pow(block_int, d, n)
    return encrypted_block_int


def decrypt_block(encrypted_block_int, e, n):
    # Decrypts a single block using RSA decryption: plaintext = ciphertext^d mod n.
    decrypted_block_int = pow(encrypted_block_int, e, n)
    decrypted_block_bytes = decrypted_block_int.to_bytes(
        (decrypted_block_int.bit_length() + 7) // 8, byteorder="big"
    )
    return decrypted_block_bytes.decode("utf-8")


def sign(message, d, n):
    # Sign the entire message by splitting it into blocks and signing each block with the private key.
    block_size = (n.bit_length() - 1) // 8
    if len(message) <= block_size:
        return [encrypt_block(message, d, n)]
    else:
        blocks = split_into_blocks(message, block_size)
        signed_blocks = [encrypt_block(block, d, n) for block in blocks]
        return blocks, signed_blocks


def verify(signed_blocks, e, n, decrypted_message):
    # Verify the signed message by decrypting each block with the public key and concatenating the results.
    decrypted_blocks = [
        decrypt_block(signed_block, e, n) for signed_block in signed_blocks
    ]
    _decrypted_message = "".join(decrypted_blocks)
    signed_message = _decrypted_message + " | " + " ".join(map(str, signed_blocks))
    return signed_message == decrypted_message, signed_message


# ---------------------------------------------------------------------------
# ------------------------Key Generation for the RSA------------------------
p, q = generate_prime(3, 5000), generate_prime(3, 5000)
while p == q:
    q = generate_prime(3, 47)

n = p * q
totient_n = (p - 1) * (q - 1)

# Find a number "e" that is coprime to the "totient_n"
e = randint(3, totient_n - 1)

while math.gcd(e, totient_n) != 1:
    e = randint(3, totient_n - 1)

d = mod_inverse(e, totient_n)
# ------------------------End of the Key Generation------------------------
# ---------------------------------------------------------------------------


print(
    f"\nPublic Key:{e}\nPrivate Key:{d}\nn:{n}\nPhi of n:{totient_n}\np:{p}\nq:{q}\n\n"
)

message = input("Enter the message: ")
blocks, signed_blocks = sign(message, d, n)

blocks_str = "".join(blocks)
signed_blocks_str = " ".join(map(str, signed_blocks))
signed_message = blocks_str + " | " + signed_blocks_str

# Take the key as an input
key_input = input("Enter the key (16 characters): ")

# Encode the signed message and the key to byte arrays.
key = bytes(key_input, "utf-8")
# Check if the key length is valid
if len(key) != 16:
    print("Error: The key must be 16 characters long.")
    exit()
signed_message_bytes = bytes(signed_message, "utf-8")
extended_signed_message = aes.pad_pkcs7(signed_message_bytes)


# Encrypt the signed message
ciphertext = aes.aes_encrypt(list(extended_signed_message), list(key))

# Decrypt the ciphertext
decrypted = aes.aes_decrypt(ciphertext, list(key))
decrypted_text = bytes(aes.unpad_pkcs7(decrypted))

# Decode the decrypted bytes to a string
verification_result, signedMessage = verify(
    signed_blocks, e, n, decrypted_text.decode("utf-8")
)


print("\nSeperated message:", blocks)
print("Signed blocks:", signed_blocks)
print("Signed message after RSA Encryption:", signed_message)
print("\nSigned message after AES Encryption:", ciphertext)
print("\nMessage after AES Decryption: ", decrypted_text.decode("utf-8"))
print(f"Signed message after RSA decryption: {signedMessage}")
print(
    f"Result of the Verification Process after RSA Decryption : {verification_result}\n"
)
