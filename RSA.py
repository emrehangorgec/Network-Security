import math
import random


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
    encoded_message = [ord(c) for c in message]
    signature = [pow(ch, d, n) for ch in encoded_message]
    return signature


# Decrypt the message by using public key, decode the decrypted message.
# Return the result of the verification process.
def verify(signature, e, n, message):
    decrypted_signature = [pow(i, e, n) for i in signature]
    decoded_message = "".join([chr(i) for i in decrypted_signature])
    return decoded_message == message


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

message = input("Enter the message: ")

# Sign the message with the private key
signature = sign(message, d, n)


# Verify the digital signature with the public key
_signature = verify(signature, e, n, message)
signed_message = message + " | " + " ".join(map(str, signature))

print(f"Result of the Verification Process: {_signature}")
print(f"Signed message is: {signed_message}\n")
# print(f"\nMessage + Signature is: {message} { ' '.join(map(str, signature))}\n")
