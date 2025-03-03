from Crypto.Random import random, get_random_bytes
from Crypto.Util.Padding import unpad
import itertools

AES_BLOCK_SIZE = 16

"""
Solution to Assignment 2

Python version 3.9 or later.

Your final submission must contain the following functions:
    - solve_padding_oracle(ctx, server)
    - find_cookie_length(server)
    - find_cookie(server)
"""

# def decrypt(ciphertext, key, iv):
#     return b""

# def last_word_oracle(ctx, server):
#     while True:
#         r = get_random_bytes(AES_BLOCK_SIZE)
#         ctr = r + ctx
#         if server(ctr) == True:
#             break
#     return r[AES_BLOCK_SIZE-1]^1 #xoring the last byte of r with 1 


# def solve_padding_oracle(ctx, server):
#     """
#     Recovers the original plaintext message from a given ciphertext using a padding oracle attack.

#     Parameters:
#         ctx (bytes): A ciphertext produced using AES in CBC mode. The first AES_BLOCK_SIZE bytes
#                      of ctx are the Initialization Vector (IV), and the remaining bytes are the ciphertext.

#         server (function): A padding oracle function with the signature:
#                                server(ciphertext: bytes) -> bool
#                            When passed a ciphertext, the server function decrypts it (using the unknown key)
#                            and returns True if the resulting plaintext has valid PKCS#7 padding,
#                            or False if the padding is invalid.

#     Returns:
#         bytes: The recovered plaintext message with the padding removed.
#     """



#     # last_word = last_word_oracle(ctx, server)
#     # decrypt(last_word)
    
#     iv = ctx[:AES_BLOCK_SIZE]
#     ciphertext = ctx[AES_BLOCK_SIZE:]
#     blocks = [ciphertext[i:i+AES_BLOCK_SIZE] for i in range(0, len(ciphertext), AES_BLOCK_SIZE)]
#     print(f"IV : {iv}")
#     print(f"Length of IV : {len(iv)}")
#     print(f"Ciphertext : {ciphertext}")
#     print(f"Length of ciphertext : {len(ciphertext)}")
#     for i in range(len(blocks)):
#         print(f"Block {i} : {blocks[i]}")
#     print(blocks[len(blocks)-1])
    
#     r = get_random_bytes(AES_BLOCK_SIZE)
#     while True:
#         i = 0
#         r = r[:AES_BLOCK_SIZE-1] + (r[AES_BLOCK_SIZE-1]^i)
#         concatenated = r + blocks[AES_BLOCK_SIZE-1]
#         if server(concatenated) == False:
#             i = i+1 
#             continue
#         else:
#             break
#         return b""
def solve_padding_oracle(ctx, server):
    """
    Recovers the original plaintext message from a given ciphertext using a padding oracle attack.

    Parameters:
        ctx (bytes): A ciphertext produced using AES in CBC mode. The first AES_BLOCK_SIZE bytes
                     of ctx are the Initialization Vector (IV), and the remaining bytes are the ciphertext.

        server (function): A padding oracle function with the signature:
                               server(ciphertext: bytes) -> bool
                           When passed a ciphertext, the server function decrypts it (using the unknown key)
                           and returns True if the resulting plaintext has valid PKCS#7 padding,
                           or False if the padding is invalid.

    Returns:
        bytes: The recovered plaintext message with the padding removed.
    """
    initialization_vector = ctx[:AES_BLOCK_SIZE]
    encrypted_blocks = ctx[AES_BLOCK_SIZE:]
    total_blocks = len(encrypted_blocks) // AES_BLOCK_SIZE
    decrypted_message = bytearray()

    for current_block_index in range(total_blocks - 1, -1, -1):
        target_block = encrypted_blocks[current_block_index * AES_BLOCK_SIZE : (current_block_index + 1) * AES_BLOCK_SIZE]
        preceding_block = encrypted_blocks[(current_block_index - 1) * AES_BLOCK_SIZE : current_block_index * AES_BLOCK_SIZE] if current_block_index > 0 else initialization_vector

        intermediate_state = bytearray(AES_BLOCK_SIZE)
        recovered_block = bytearray(AES_BLOCK_SIZE)

        for byte_index in range(AES_BLOCK_SIZE - 1, -1, -1):
            padding_size = AES_BLOCK_SIZE - byte_index
            byte_found = False

            for guess_byte in range(256):
                modified_preceding = bytearray(preceding_block)
                modified_preceding[byte_index] = guess_byte

                for k in range(byte_index + 1, AES_BLOCK_SIZE):
                    modified_preceding[k] = intermediate_state[k] ^ padding_size

                if server(bytes(modified_preceding) + target_block):
                    if byte_index > 0:
                        modified_preceding[byte_index - 1] ^= 1 
                        if not server(bytes(modified_preceding) + target_block):
                            continue  

                    intermediate_state[byte_index] = guess_byte ^ padding_size
                    recovered_block[byte_index] = intermediate_state[byte_index] ^ preceding_block[byte_index]
                    byte_found = True
                    break

            if not byte_found:
                raise Exception("Failed to recover a valid padding byte.")

        decrypted_message = recovered_block + decrypted_message

    # Remove PKCS7 padding
    padding_length = decrypted_message[-1]
    return bytes(decrypted_message[:-padding_length])

# def solve_padding_oracle(ctx, server):
#     return b""
#     """
#     Recovers the original plaintext message from a given ciphertext using a padding oracle attack.

#     Parameters:
#         ctx (bytes): A ciphertext produced using AES in CBC mode. The first AES_BLOCK_SIZE bytes
#                      of ctx are the Initialization Vector (IV), and the remaining bytes are the ciphertext.

#         server (function): A padding oracle function with the signature:
#                                server(ciphertext: bytes) -> bool
#                            When passed a ciphertext, the server function decrypts it (using the unknown key)
#                            and returns True if the resulting plaintext has valid PKCS#7 padding,
#                            or False if the padding is invalid.

#     Returns:
#         bytes: The recovered plaintext message with the padding removed.
#     """

#     # Extract IV and ciphertext
#     iv = ctx[:AES_BLOCK_SIZE]
#     ciphertext = ctx[AES_BLOCK_SIZE:]

#     # Break the ciphertext into 16-byte blocks
#     blocks = [iv] + [ciphertext[i: i + AES_BLOCK_SIZE] for i in range(0, len(ciphertext), AES_BLOCK_SIZE)]

#     recovered_plaintext = b''

#     # Process each block from last to first
#     for block_index in range(len(blocks) - 1, 0, -1):
#         prev_block = blocks[block_index - 1]  # The IV or previous ciphertext block
#         curr_block = blocks[block_index]  # The ciphertext block being decrypted
#         decrypted_block = bytearray(AES_BLOCK_SIZE)
#         intermediate_state = bytearray(AES_BLOCK_SIZE)

#         # Attack each byte in the block from last to first
#         for padding_length in range(1, AES_BLOCK_SIZE + 1):
#             modified_prev_block = bytearray(prev_block)

#             # Adjust previously found intermediate values to ensure correct padding
#             for j in range(1, padding_length):
#                 modified_prev_block[-j] = prev_block[-j] ^ intermediate_state[-j] ^ padding_length

#             # Brute-force the current byte
#             found = False
#             for guess in range(256):
#                 modified_prev_block[-padding_length] = prev_block[-padding_length] ^ guess ^ padding_length
#                 modified_ciphertext = bytes(modified_prev_block) + curr_block

#                 if server(modified_ciphertext):  # Valid padding means correct guess
#                     intermediate_state[-padding_length] = guess
#                     decrypted_block[-padding_length] = guess ^ prev_block[-padding_length]
#                     found = True
#                     break
            
#             if not found:
#                 raise Exception("Padding oracle attack failed.")

#         # Add the recovered block to the final plaintext
#         recovered_plaintext = bytes(decrypted_block) + recovered_plaintext

#     # Remove PKCS#7 padding
#     return unpad(recovered_plaintext, AES_BLOCK_SIZE, style="pkcs7")

def find_cookie_length_1(device):
    
    # a = device(b"")
    # print(a)
    # print(len(a))
    # print(a[15])
    
    return 0



def find_cookie_length(device):
    """
    Determines the length (in bytes) of a secret cookie that the device appends to a plaintext message
    before encryption.

    Parameters:
        device (function): A stateful CBC encryption oracle with the signature:
                               device(path: bytes) -> bytes
                           The device takes a bytes object "path" as input and internally constructs a message:
                               msg = path + b";cookie=" + cookie
                           It then pads and encrypts this message using AES in CBC mode.
                           Importantly, the device retains its CBC state between calls, so the encryption is stateful.

    Returns:
        int: The length of the secret cookie (in bytes).
    """
    
    # cookie_length = 0
    # resource_path = b""
    # # encrypted1 = device(resource_path)
    # print(device(resource_path))
    # # print(device(resource_path))
    # print(len(device(resource_path)))
    # print(len(b"aaa" + b";cookie=") + 5)
    # print(f"For resource path b\"\" : {len(device(b""))}")
    # print(f"For resource path b\"a\" : {len(device(b"a"))}")
    # print(f"For resource path b\"aa\" : {len(device(b"aa"))}")
    # print(f"For resource path b\"aaa\" : {len(device(b"aaa"))}")
    # rp1 = get_random_bytes(16)
    # print(f"For resource path of length {len(rp1)} : {len(device(rp1))}")
    # rp2 = get_random_bytes(15)
    # print(f"For resource path of length {len(rp2)} : {len(device(rp2))}")
    # rp3 = get_random_bytes(14)
    # print(f"For resource path of length {len(rp3)} : {len(device(rp3))}")
    # rp4 = get_random_bytes(13)
    # print(f"For resource path of length {len(rp4)} : {len(device(rp4))}")
    # rp5 = get_random_bytes(10)
    # print(f"For resource path of length {len(rp5)} : {len(device(rp5))}")
    # rp6 = get_random_bytes(18)
    # print(f"For resource path of length {len(rp6)} : {len(device(rp6))}")
    # rp7 = get_random_bytes(20)
    # print(f"For resource path of length {len(rp7)} : {len(device(rp7))}")
    # rp8 = get_random_bytes(21)
    # print(f"For resource path of length {len(rp8)} : {len(device(rp8))}")
    # rp9 = get_random_bytes(25)
    # print(f"For resource path of length {len(rp9)} : {len(device(rp9))}")
    # rp10 = get_random_bytes(32)
    # print(f"For resource path of length {len(rp10)} : {len(device(rp10))}")
    # rp11 = get_random_bytes(0)
    # print(f"For resource path of length {len(rp11)} : {len(device(rp11))}")
    # rp12 = get_random_bytes(17)
    # print(f"For resource path of length {len(rp12)} : {len(device(rp12))}")
    # rp13 = get_random_bytes(18)
    # print(f"For resource path of length {len(rp13)} : {len(device(rp13))}")
    # rp14 = get_random_bytes(19)
    # print(f"For resource path of length {len(rp14)} : {len(device(rp14))}")
    cookie_length = 0
    empty_resource_path = len(device(b""))
    # print(empty_resource_path)
    for i in range(1,1000,1):
        test_resource_path = get_random_bytes(i)
        # length_of_path = len(p)
        # print(f"resource path length : {len(test_resource_path)} --> {len(device(test_resource_path))}")
        if(len(device(test_resource_path)) > empty_resource_path):
            empty_resource_path = len(device(test_resource_path))
            identifier_length_change_at_position = i
            break
    # print(f"identifier_length_change_at_position : {i}")
    # print(len(device(get_random_bytes(identifier_length_change_at_position-1))))
    # print(len(b";cookie="))
    # print(len(get_random_bytes(identifier_length_change_at_position-1)))
    cookie_length = len(device(get_random_bytes(identifier_length_change_at_position-1))) - len(b";cookie=") - len(get_random_bytes(identifier_length_change_at_position-1)) - 1 # -1 for padding
    # print(f"cookie_length : {cookie_length}") 
    
    return cookie_length


def find_cookie(device):
    """
    Recovers the complete cookie encrypted by the device.
    
    Args:
        device: The compromised device function that encrypts the path and cookie.
    
    Returns:
        The recovered cookie as a bytes object.
    """
    cookie_len = find_cookie_length(device)
    cookie = bytearray()
    block_size = 16
    
    for i in range(cookie_len):
        prefix_len = (15 - (len(b";cookie=") + i)) % block_size
        setup_path = b"A" * prefix_len
        ctx_setup = device(setup_path)
        target_block = ctx_setup[block_size:2*block_size] if len(ctx_setup) > block_size else ctx_setup
        
        for g in range(256):
            path = setup_path + bytes(cookie) + bytes([g])
            ctx_probe = device(path)
            target = ctx_probe[block_size:2*block_size] if len(ctx_probe) > block_size else ctx_probe
            
            if target == target_block:
                cookie.append(g)
                break
    
    return bytes(cookie)