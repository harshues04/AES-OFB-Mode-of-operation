import base64
import binascii
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def get_key(key_input):
    try:
        if len(key_input) == 32: 
            return binascii.unhexlify(key_input)
        elif len(key_input) == 24:  
            return base64.b64decode(key_input)
        else:
            raise ValueError("Key must be 128-bit: 32 hex chars or 24 base64 chars (including padding).")
    except Exception as e:
        raise ValueError(f"Invalid key: {e}")

def encrypt_ofb(plaintext, key):
    iv = get_random_bytes(16)  
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return iv, ciphertext

def decrypt_ofb(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext

def main():
    plaintext = input("Enter plaintext: ").strip()
    
    key_input = input("Enter 128-bit key (hex or base64): ").strip()
    key = get_key(key_input)
    
    iv, ciphertext = encrypt_ofb(plaintext, key)
    
    print("\n--- Encryption ---")
    print(f"Plaintext: {plaintext}")
    print(f"Key (hex): {key.hex()}")
    print(f"IV (hex): {iv.hex()}")
    print(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode('utf-8')}")
    
    decrypted = decrypt_ofb(ciphertext, key, iv)
    print("\n--- Decryption ---")
    print(f"Decrypted: {decrypted}")
    if decrypted == plaintext:
        print("Verification: Success (original plaintext recovered)")
    else:
        print("Verification: Failure")

if __name__ == "__main__":
    main()