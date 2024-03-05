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


def sign(message, d, n):
    signature = [pow(ch, d, n) for ch in message]
    return signature


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

print(f"Public Key:{e}\nPrivate Key:{d}")
print(f"n:{n}\nPhi of n:{totient}")
print(f"p:{p}\nq:{q}")


# Sign the message
message = "Hello"
encoded_message = [ord(c) for c in message]
signature = sign(encoded_message, d, n)
# print(f"Message is {message}")
# print(f"Signature is: {signature}")

# Verification
_signature = verify(signature, e, n, message)
print(f"Result of Verification Process: {_signature}")
