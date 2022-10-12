import math
import random

import hashlib
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import random

"""
Information about Alice and Bob's agreement

# The hashing algorithm used between the peers is sha512 from the hashlib library and asymmetric cryptography using cryptography.hazmat library.
# They have agreed upon using this hashing algorithm and asymmetric cryptography tool beforehand.


Link on how to use cryptography.hazmat library
https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

Original docs:
https://cryptography.io/en/latest/

"""

public_exponent = 65537

alice_randomness = None
alice_hit = None
bob_randomness = None
bob_hit = None

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


def fault_hit(hit):
    return hit > 6 or hit < 1


def set_randomness_and_hit_by_id(player_id, hit, randomness):
    global alice_randomness
    global alice_hit
    global bob_randomness
    global bob_hit

    if player_id == 1 and alice_randomness is None and alice_hit is None:
        alice_randomness = randomness
        alice_hit = hit
    elif player_id == 2 and bob_randomness is None and bob_hit is None:
        bob_randomness = randomness
        bob_hit = hit

def hit_pack_and_send(playerId, key, randomness):
    current_player, opposite_player = get_player_by_id(playerId)

    try:
        dice_hit = int(
        input(current_player + ", please hit the dice and send it over to " + opposite_player + " by typing your number in the terminal: "))
    except:
        return False

    if fault_hit(dice_hit):
        print("\nPlease hit between 1 and 6! Do not cheat!\n")
        return False

    print(current_player + " hit: " + str(dice_hit) + "\n")
    time.sleep(3)

    print(current_player + " now commits their message using hash based commitment:")
    hash = commitment(randomness, dice_hit)
    set_randomness_and_hit_by_id(playerId, dice_hit, randomness)
    print(hash)
    time.sleep(3)

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

    print(current_player + " now encrypts their message.....")
    encrypted_message = encrypt_message(key.public_key(), hash)
    print(encrypted_message)
    time.sleep(4)

    print( "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

    print(opposite_player + " has now received the message from " + current_player + " and is going to decrypt it")
    print("Decrypting message....")
    time.sleep(4)
    hash_after_decryption = decrypt_message(key, encrypted_message)
    print("Hash after decrypting: " + str(hash_after_decryption))

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

    return (hash_after_decryption, True)


def reveal(player_id, hash):
    global bob_randomness
    if player_id == 1:
        print("As a reminder, the current hash Alice has in her hands from before is: \n \n " + str(hash) + " \n \n")
        time.sleep(8)
        print("Bob is now sending over his randomness and m over to Alice...")
        time.sleep(5)
        print((bob_randomness, bob_hit))

        print()

        print("Alice now calculates her own version of the hash by appending the randomness and m together using sha512.... \n")
        time.sleep(4)
        alices_own_version_of_hash = sha512_hashing(bob_randomness, bob_hit)
        print(str(alices_own_version_of_hash))
        print()
        time.sleep(3)
        print("Shes now comparing her own version ....")
        time.sleep(3)
        print("Did Bob tell the truth?? " + str(is_both_hashes_equal(hash, alices_own_version_of_hash)) + " \n")

    elif player_id == 2:
        print("As a reminder, the current hash Bob has in her hands from before is: \n \n " + str(hash) + " \n \n")
        print("Alice is now sending over her randomness and m over to Bob...\n")
        time.sleep(3)
        print((alice_randomness, alice_hit))

        print()

        print(
            "Bob now calculates his own version of the hash by appending the randomness and m together using sha256....")
        time.sleep(4)
        bob_own_version_of_hash = sha512_hashing(alice_randomness, alice_hit)
        print()
        print(str(bob_own_version_of_hash))
        print()
        print("He is now comparing his own version ....")
        print()
        time.sleep(3)
        print("Did Alice tell the truth?? " + str(is_both_hashes_equal(hash, bob_own_version_of_hash)))


def get_player_by_id(player_id):
    current_player, opposite_player = "", ""

    if player_id == 1:
        current_player = "Alice"
        opposite_player = "Bob"
    elif player_id == 2:
        current_player = "Bob"
        opposite_player = "Alice"

    return current_player, opposite_player


def reset():
    bob_randomness, bob_hit, alice_randomness, alice_hit = None, None, None, None



def test():
    while True:
        global alice_hit
        global bob_hit

        alice_id = 1
        alice_key = generate_key()
        alice_hash_from_bob = None

        bob_id = 2
        bob_key = generate_key()
        bob_hash_from_alice = None


        print("\nREAD CAREFULLY!!! :D \n")
        print(
            "Bob and Alice both agree on using sha512 hashing algorithm and asymmetric cryptography from the cryptography.hazmat library")
        time.sleep(7)
        print()
        print("Generating Alice's key...")
        time.sleep(5)

        print(alice_key.public_key().public_numbers())
        print("Sending over Alice's public key to Bob...")
        time.sleep(2)
        print()

        print("Generating Bob's key....")
        time.sleep(5)
        print(bob_key.public_key().public_numbers())
        print("Sending over Bob's public key to Alice....\n")
        time.sleep(2)
        print("We are ready to go!! Both parties have now received each others public key!")
        time.sleep(2)
        print(
            "\n ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

        print(
            "                                                                              Welcome to Bob's and Alice's dice game!!  \n")
        print()
        print(
            "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

        print("Starting the process where Alice sends her hashed commitment and encrypted message to Bob\n")
        current_user_turn = 1  ## Controlling who's turn it is to hit the dice
        current_state = 1  ## The current state of the game. State 1 is the commitment phase, State 2 is the reveal phase (to see who lied), State 3 is phase to see who won

        while True:

            ## Start of the game
            if current_state == 1:
                ## Alice's turn
                if current_user_turn == 1:
                    alice_randomness = random.randint(3456456452342342323423534, 3457567453445634634634634534)
                    bob_hash_from_alice, valid_hit = hit_pack_and_send(alice_id, alice_key, alice_randomness)
                    if valid_hit and bob_hash_from_alice is not None:
                        current_user_turn = 2

                ## Bob's turn
                elif current_user_turn == 2:
                    bob_randomness = random.randint(4252342343453234234234234, 3453453463244523452634634534)
                    alice_hash_from_bob, valid_hit = hit_pack_and_send(bob_id, bob_key, bob_randomness)
                    if valid_hit and bob_hash_from_alice is not None and alice_hash_from_bob is not None:
                        current_state = 2
                        current_user_turn = 1
                        print("It's time for reveal!!")
                        time.sleep(5)


            elif current_state == 2:
                current_playername, opposite_playername = get_player_by_id(current_user_turn)

                if (current_user_turn == 1):
                    print("Starting off with " + current_playername + " \n")
                    reveal(current_user_turn, alice_hash_from_bob)
                    current_user_turn = 2
                elif current_user_turn == 2:
                    print("Next, " + current_playername)
                    reveal(current_user_turn,bob_hash_from_alice)
                    current_state = 3

            elif current_state == 3:
                print("Alice hits: " + str(alice_hit))
                print("bob hits: " + str(bob_hit))
                if alice_hit > bob_hit:
                    print("Alice won!!!")
                elif bob_hit > alice_hit:
                    print("Bob won!!!")
                else:
                    print("Tie! :( \n")

                time.sleep(2)

                cont = input("The game is over! Press p to go again or any other character to quit")
                if cont == 'p':
                    reset()
                    break
                else:
                   return

test()
