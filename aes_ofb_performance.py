import base64
import binascii
import time
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def get_key(key_input):
    """Parse 128-bit (16-byte) key from hex or base64."""
    try:
        if len(key_input) == 32:  # Hex
            return binascii.unhexlify(key_input)
        elif len(key_input) == 24:  # Base64
            return base64.b64decode(key_input)
        else:
            raise ValueError("Key must be 128-bit: 32 hex chars or 24 base64 chars.")
    except Exception as e:
        raise ValueError(f"Invalid key: {e}")

def encrypt_ofb_file(input_file, output_file, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    
    start_time = time.time()
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(iv)  # Store IV at start of ciphertext file
        while chunk := f_in.read(1024 * 1024):  # Read in chunks
            ciphertext = cipher.encrypt(chunk)
            f_out.write(ciphertext)
    enc_time = time.time() - start_time
    
    return enc_time, os.path.getsize(output_file)

def decrypt_ofb_file(input_file, output_file, key):
    with open(input_file, 'rb') as f_in:
        iv = f_in.read(16)
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
        
        start_time = time.time()
        with open(output_file, 'wb') as f_out:
            while chunk := f_in.read(1024 * 1024):
                plaintext = cipher.decrypt(chunk)
                f_out.write(plaintext)
        dec_time = time.time() - start_time
    
    return dec_time

def main():
    input_file = 'test_1mb.txt'
    enc_file = 'encrypted.bin'
    dec_file = 'decrypted.txt'
    
    # Input key
    key_input = input("Enter 128-bit key (hex or base64): ").strip()
    key = get_key(key_input)
    
    # Encrypt
    enc_time, ct_size = encrypt_ofb_file(input_file, enc_file, key)
    
    # Decrypt
    dec_time = decrypt_ofb_file(enc_file, dec_file, key)  # Fixed: Added 'key' parameter
    
    # Verify
    with open(input_file, 'rb') as f_orig, open(dec_file, 'rb') as f_dec:
        if f_orig.read() == f_dec.read():
            print("Verification: Success")
        else:
            print("Verification: Failure")
    
    # Output results
    print("\nPerformance Results:")
    print(f"Encryption Time: {enc_time:.4f} seconds")
    print(f"Decryption Time: {dec_time:.4f} seconds")
    print(f"Ciphertext Size: {ct_size} bytes")

if __name__ == "__main__":
    main()