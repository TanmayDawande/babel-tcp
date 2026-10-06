import hashlib
import os
import struct


def mgf1(seed: bytes, target_length: int) -> bytes:
    output = b""
    counter = 0
    while len(output) < target_length:
        C = struct.pack("!I", counter)
        output += hashlib.sha256(seed + C).digest()
        counter += 1
    return output[:target_length]

def oaep_pad(msg_bytes, k):
    HLen = 32
    lHash = hashlib.sha256(b"").digest()
    pad_len = k - len(msg_bytes) - (2 * 32)- 2 #for 0x00 and 0x01
    PS = b'\x00' * pad_len
    DB = lHash + PS + b'\x01' + msg_bytes
    seed = os.urandom(HLen)

    First = mgf1(seed, len(DB))

    maskedDB = bytes(b1^b2 for b1, b2 in zip(DB, First))

    Second = mgf1(maskedDB, len(seed))

    maskedSeed = bytes(b1^b2 for b1, b2 in zip(seed, Second))

    encryptMSG = b'\x00' + maskedSeed + maskedDB

    return encryptMSG

def oaep_unpad(em):
    lHash_local = hashlib.sha256(b"").digest()

    y = em[0:1]
    maskedSeed = em[1:33]
    maskedDB = em[33:]

    first = mgf1(maskedDB, 32)
    seed = bytes(b1^b2 for b1, b2 in zip(maskedSeed, first))

    second = mgf1(seed, len(maskedDB))
    db = bytes(b1^b2 for b1, b2 in zip(maskedDB, second))

    lHash_received = db[:32]
    
    if y != b'\x00':
        raise ValueError("Decryption failed: First byte is not zero.")
    if lHash_received != lHash_local:
        raise ValueError("Decryption failed: Hash mismatch (Tampering detected!).")
        

    index = 32 
    while index < len(db) and db[index] == 0x00:
        index += 1
        
    if index >= len(db) or db[index] != 0x01:
        raise ValueError("Decryption failed: Padding boundary 0x01 not found.")
        
    # Grab everything AFTER the 0x01 byte!
    message = db[index + 1:]
    
    return message

    

