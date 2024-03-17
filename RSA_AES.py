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


# Encode the message to ASCII values, sign it by using private key.
def sign(message, d, n):
    # encoded_message = [ord(c) for c in message]
    message = bytes(message, "ascii")
    signature = [pow(ch, d, n) for ch in message]
    return signature


# Decrypt the message by using public key, decode the decrypted message.
# Return the result of the verification process.
def verify(signature, e, n, decrypted_text):
    decrypted_signature = [pow(i, e, n) for i in signature]
    decoded_message = "".join([chr(i) for i in decrypted_signature])
    signed_message = decoded_message + " | " + " ".join(map(str, signature))
    decrypted_text = decrypted_text.decode("utf-8")
    return signed_message == decrypted_text


# Key Generation for the RSA
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
# End of the Key Generation


print(
    f"\nPublic Key:{e}\nPrivate Key:{d}\nn:{n}\nPhi of n:{totient_n}\np:{p}\nq:{q}\n\n"
)

plaintext = input("Enter the plaintext: ")

# Sign the plaintext with the private key
signature = sign(plaintext, d, n)
# Take the key as an input
key_input = input("Enter the key (16 characters): ")

# Convert the signature and key to byte arrays
key = bytes(key_input, "utf-8")
# Convert the signed message to bytes
signed_message = plaintext + " | " + " ".join(map(str, signature))
signed_message_bytes = bytes(signed_message, "utf-8")

padded_signed_message = aes.pad_pkcs7(signed_message_bytes)


# Check if the key length is valid
if len(key) != 16:
    print("Error: The key must be 16 characters long.")
    exit()


# Encrypt the plaintext
encrypted = aes.aes_encrypt(list(padded_signed_message), list(key))
print("Encrypted:", encrypted)

# Decrypt the ciphertext
decrypted = aes.aes_decrypt(encrypted, list(key))
decrypted_text = bytes(aes.unpad_pkcs7(decrypted))

# Convert the decrypted bytes back to a string
print("Decrypted text:", decrypted_text.decode("utf-8"))


# Verify the digital signature with the public key
_signature = verify(signature, e, n, decrypted_text)
signed_message = plaintext + " | " + " ".join(map(str, signature))

print(f"Result of the Verification Process: {_signature}")
print(f"Signed message is: {signed_message}\n")
# print(f"\nMessage + Signature is: {message} { ' '.join(map(str, signature))}\n")
