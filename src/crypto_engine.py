import math
import rsa_encrypt
import os
from Crypto.Cipher import AES

def generate_cyphertext(message, N, e):
    message_bytes = message.encode('utf-8')
    M = int.from_bytes(message_bytes, byteorder='big')
    # print(f"{pow(M, e, N)}") debugging
    return f"{pow(M, e, N)}"

def decrypt(C, N, d):
    C = int(C)
    # print(C) debugging 
    M_decrypted = pow(C, d, N)
    bit_length = math.ceil(M_decrypted.bit_length() / 8)
    #this calculates the bytelehgth which is needed in the to_bytes
    decrypt_bytes = M_decrypted.to_bytes(bit_length, byteorder="big")
    return decrypt_bytes.decode('utf-8')

def encrypt_aes(message, aes_key):
    message = message.encode('utf-8')
    nonce = os.urandom(16)
    aes_obj = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    cyphertext, tag = aes_obj.encrypt_and_digest(message)
    return nonce+tag+cyphertext

def decrypt_aes(payload, aes_key):
    nonce = payload[:16]
    tag = payload[16:32]
    ciphertext = payload[32:]
    aes_obj = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    message_bytes = aes_obj.decrypt_and_verify(ciphertext, tag)
    return message_bytes.decode('utf-8')

