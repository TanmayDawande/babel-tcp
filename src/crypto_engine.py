import math
import oaep
import os
from Crypto.Cipher import AES

def generate_cyphertext(message, N, e):
    padded_bytes = oaep.oaep_pad(message, 256)
    M = int.from_bytes(padded_bytes, byteorder='big')
    # print(f"{pow(M, e, N)}") debugging
    C = pow(M, e, N)
    return C.to_bytes(256, byteorder='big')


def decrypt(Ciphertext_bytes, N, d):
    C = int.from_bytes(Ciphertext_bytes, byteorder='big')
    # print(C) debugging 
    M_decrypted = pow(C, d, N)
    padded_box = M_decrypted.to_bytes(256, byteorder='big')
    original_message_bytes = oaep.oaep_unpad(padded_box)
    return original_message_bytes

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

