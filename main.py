import math
import random

import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import random

"""
Information about Alice and Bob's agreement

# The hashing algorithm used between the peers is sha512 from the hashlib library and asymmetric cryptography using cryptography.hazmat library.
# They have agreed upon using this hashing algorithm and asymmetric cryptography tool beforehand.


Link to cryptography.hazmat
https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

"""

public_exponent = 65537


def hit_dice():
    return random.randint(1, 6)

# Generate the key that Alice and Bob is going to use
def generate_key():
    return rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=2048,
        backend=default_backend()
    )


# Encrypt the message using the target's public key
def encrypt_message(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )


# Decrypt the message using the target's private key
def decrypt_message(private_key, encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )


# Hash the commitment with a randomness and the random number of dice (integer between 1-6)
def sha512_hashing(randomness, message):
    return hashlib.sha256(str(randomness + message).encode("utf-8")).digest()


def commitment(randomness, message):
    return sha512_hashing(randomness, message)


# Send over the randomness and message for the parties to reveal to make sure nobody is lying
def send_r_and_m(r, m):
    return r, m


# Check if both hashes are equal
def is_both_hashes_equal(first_hash, second_hash):
    return first_hash == second_hash


def test():
    bob_key = generate_key()
    alice_key = generate_key()

    print()
    print()
    print("Alice public key: ")
    print(alice_key.public_key().public_numbers())

    print()

    print("Bob public key: ")
    print(bob_key.public_key().public_numbers())

    print("\n ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

    print("                                                                              Welcome to bob and alice dice game!!  \n")
    print()
    print("Starting the process where Alice sends her hashed commitment and encrypted message to Bob")
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

    print("Bob sends his public key to Alice:")
    print(bob_key.public_key().public_numbers())
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

    print("Alice now commits her message using hash based commitment:")
    his_hash = commitment(123123123123, 5)
    print(his_hash)
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

    print("Alice now encrypts her message.....")
    encrypted_message = encrypt_message(bob_key.public_key(), his_hash)
    print(encrypted_message)
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

    print("Bob has now received his message from Alice and is going to decrypt it now")

    print("Decrypting message....")
    hash_after_decryption = decrypt_message(bob_key, encrypted_message)
    print(hash_after_decryption)
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

    print("It's time for reveal!!")
    print("Alice sends over r and m for reveal and Bob checks if the hashes are the same")
    r, m = send_r_and_m(123123123123, 5)
    print(r, m)
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

    print("Did Alice send over her real number at the beginning? Checking hashes...")
    # Encrypt the message 2000 to bob
    my_own_hash = sha512_hashing(r, m)
    print(is_both_hashes_equal(my_own_hash, his_hash))


test()
