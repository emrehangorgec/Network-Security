# Implementation of the RSA algorithm without using external libraries
# to generate digital signature and verification

import math
import random


def is_prime(number):
    if number < 2:
        return False
    for i in range(2, int(number**0.5) + 1):
        if number % i == 0:
            return False
    return True


def randint(min_value, max_value):
    return random.randint(min_value, max_value)


def generate_prime(min_value, max_value):
    prime = randint(min_value, max_value)
    while not is_prime(prime):
        prime = randint(min_value, max_value)
    return prime


def mod_inverse(e, totient):
    d = 3
    while (d * e) % totient != 1:
        d += 1
    return d


# Encode the message to ASCII values, sign it by using private key.
def sign(message, d, n):
    encoded_message = [ord(c) for c in message]
    signature = [pow(ch, d, n) for ch in encoded_message]
    return signature


# Decrypt the message by using public key, decode the decrypted message.
def verify(signature, e, n, message):
    decrypted_signature = [pow(i, e, n) for i in signature]
    decoded_message = "".join([chr(i) for i in decrypted_signature])
    return decoded_message == message


# Key Generation
p, q = generate_prime(3, 5000), generate_prime(3, 5000)
while p == q:
    q = generate_prime(3, 47)

n = p * q
totient = (p - 1) * (q - 1)

e = randint(3, totient - 1)

while math.gcd(e, totient) != 1:
    e = randint(3, totient - 1)

d = mod_inverse(e, totient)
# End of Key Generation


print(f"Public Key:{e}\nPrivate Key:{d}\nn:{n}\nPhi of n:{totient}\np:{p}\nq:{q}\n\n")

message = input("Enter the message: ")

# Sign the message with private key.
signature = sign(message, d, n)


# Verify the digital signature with public key
_signature = verify(signature, e, n, message)

print(f"\nResult of the Verification Process: {_signature}")
print(f"\nMessage + Signature is: {message} { ' '.join(map(str, signature))}\n")
