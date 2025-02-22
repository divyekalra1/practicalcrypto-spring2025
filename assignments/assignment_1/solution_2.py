# Python version 3.9 or later

# Complete the functions below and include this file in your submission.
#
# You can verify your solution by running `problem_2.py`. See `problem_2.py` for more
# details.

# ------------------------------------- IMPORTANT --------------------------------------
# Do NOT modify the name or signature of the three functions below. You can, however,
# add any additional functons to this file.
# --------------------------------------------------------------------------------------

# Given a ciphertext enciphered using the Caesar cipher, recover the plaintext.
# In the Caesar cipher, each byte of the plaintext is XORed by the key (which is a
# single byte) to compute the ciphertext.
#
# The input `ciphertext` is a bytestring i.e., it is an instance of `bytes`
# (see https://docs.python.org/3.9/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview).
# The function should return the plaintext, which is also a bytestring.

import itertools
from collections import Counter

def calculate_frequency_score(text):
    letter_frequencies = {
        'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
        'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
        'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
        'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
        'u': 2.758, 'v': 0.978, 'w': 2.361, 'x': 0.150, 'y': 1.974, 'z': 0.074,
        ' ': 15.0
    }
    return sum(letter_frequencies.get(chr(byte).lower(), 0) for byte in text)

def compute_text_score(text):
    frequency_map = {
        'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
        'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
        'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
        'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
        'u': 2.758, 'v': 0.978, 'w': 2.361, 'x': 0.150, 'y': 1.974, 'z': 0.074,
        ' ': 15.0
    }
    return sum(frequency_map.get(chr(byte).lower(), 0) for byte in text if chr(byte).lower() in frequency_map)

def break_caesar_cipher(ciphertext):
    # TODO: Update the body to compute the plaintext

    highest_score = 0
    best_decoded_text = None
    
    for shift_key in range(256):
        decoded_text_candidate = bytes(byte ^ shift_key for byte in ciphertext)
        candidate_score = compute_text_score(decoded_text_candidate)

        if candidate_score > highest_score:
            highest_score = candidate_score
            best_decoded_text = decoded_text_candidate

    return best_decoded_text

# Given a ciphertext enciphered using a Vigenere cipher, find the length of the secret
# key using the 'index of coincidence' method.
#
# The input `ciphertext` is a bytestring.
# The function returns the key length, which is an `int`.

def divide_bytestring(byte_string: bytes, num_groups: int):
    groups = [b'' for _ in range(num_groups)]
    
    for i, byte in enumerate(byte_string):
        groups[i % num_groups] += bytes([byte])
    
    return groups

def ioc(byte_string: bytes) -> float:
    n = len(byte_string)
    if n <= 1:
        return 0.0
    
    frequency = Counter(byte_string)
    ic = sum(f * (f - 1) for f in frequency.values()) / (n * (n - 1))
    
    return ic    
def find_vigenere_key_length(ciphertext):
    # TODO: Update the body to find the key length

    avg_ioc = [0] * 26
    for ii in range(26):
        key_length = ii+1
        index_of_coincidence = [0] * key_length
        groups = divide_bytestring(ciphertext, key_length)
        for i in range(key_length):
            index_of_coincidence[i] = ioc(groups[i])    
        avg_ioc[ii] = sum(index_of_coincidence) / key_length
        
    closest_to_english_ioc = min(range(len(avg_ioc)), key=lambda i: abs(avg_ioc[i] - 0.067))

    # print(closest_to_english_ioc)
    # print(avg_ioc[closest_to_english_ioc])
    return closest_to_english_ioc+1 


# Given a ciphertext enciphered using a Vigenere cipher and the length of the key, 
# recover the plaintext.
#
# The input `ciphertext` is a bytestring.
# The function should return the plaintext, which is also a bytestring.



# A more naive approach
# def break_vigenere_cipher(ciphertext, key_length):
#     # TODO: Update the body to compute the plaintext

#     print(find_vigenere_key_length(ciphertext))
#     alphabets = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
#     # keywords = [''.join(i) for i in itertools.product(alphabets, repeat = key_length)]
#     keywords = itertools.permutations(alphabets, key_length)
#     keywords_bytes = []
#     for p in keywords:
#         bytestring = ''.join(p).encode('utf-8')
#         keywords_bytes.append(bytestring)  # Convert the joined permutation to a byte string
#     keywords_bytes_repeated = [match_string_length(s, ciphertext) for s in keywords_bytes]
#     decrypted_plaintext = []    
#     for i in range(len(ciphertext)):
#         decrypted_plaintext.append(bytes((b1 - b2) & 0xFF for b1, b2 in zip(keywords_bytes_repeated[i], ciphertext)))
#     index_of_coincidence = [ioc(decrypted_plaintext[i]) for i in range(len(decrypted_plaintext))]
#     closest_to_english_ioc = min(range(len(index_of_coincidence)), key=lambda i: abs(index_of_coincidence[i] - 0.067))
    
#     return bytes(decrypted_plaintext[closest_to_english_ioc])



def break_single_byte_xor(ciphertext):
    best_score = 0
    best_key = None
    best_decryption = None

    for key_candidate in range(256):
        decrypted_text = bytes([byte ^ key_candidate for byte in ciphertext])
        score = calculate_frequency_score(decrypted_text)

        if score > best_score:
            best_score = score
            best_key = key_candidate
            best_decryption = decrypted_text

    return best_key, best_decryption, best_score

def break_vigenere_cipher(ciphertext, key_length):
    groups = divide_bytestring(ciphertext, key_length)
    key_bytes = []

    for group in groups:
        key_byte, _, _ = break_single_byte_xor(group)
        key_bytes.append(key_byte)

    key = bytes(key_bytes)
    plaintext = bytes([byte ^ key[i % key_length] for i, byte in enumerate(ciphertext)])

    return plaintext
