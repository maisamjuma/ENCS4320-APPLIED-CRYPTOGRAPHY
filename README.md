# ENCS4320-APPLIED-CRYPTOGRAPHY
# README

 TEA (Tiny Encryption Algorithm) Implementation

This project provides an implementation of the Tiny Encryption Algorithm (TEA) in both Electronic Code Book (ECB) and Cipher Block Chaining (CBC) modes. It includes functions for encrypting and decrypting plaintext, as well as BMP image files.

	Features
- Encrypt and decrypt plaintext using TEA:
  
def tea_encrypt_block(block, key):
    L, R = block
    K0, K1, K2, K3 = key
    delta = 0x9E3779B9
    sum = 0
    for _ in range(32):
        sum = (sum + delta) & 0xFFFFFFFF
        L = (L + (((R << 4) + K0) ^ (R + sum) ^ ((R >> 5) + K1))) & 0xFFFFFFFF
        R = (R + (((L << 4) + K2) ^ (L + sum) ^ ((L >> 5) + K3))) & 0xFFFFFFFF
    return (L, R)


def tea_decrypt_block(block, key):
    L, R = block
    K0, K1, K2, K3 = key
    delta = 0x9E3779B9
    sum = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        R = (R - (((L << 4) + K2) ^ (L + sum) ^ ((L >> 5) + K3))) & 0xFFFFFFFF
        L = (L - (((R << 4) + K0) ^ (R + sum) ^ ((R >> 5) + K1))) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF
    return (L, R)

-Encrypt and decrypt plaintext and BMP image files, leaving the first 10 blocks (80 bytes) unencrypted, using TEA in both modes CBC and ECB :

def ecb_mode_encrypt(plaintext, key):
    plaintext = pad_plaintext(plaintext)
    encrypted = bytearray()

    for i in range(0, len(plaintext), 8):
        if i < 80:  # Leave first 10 blocks (80 bytes) unencrypted
            encrypted.extend(plaintext[i:i + 8])
        else:
            block = (int.from_bytes(plaintext[i:i + 4], byteorder='big'),
                     int.from_bytes(plaintext[i + 4:i + 8], byteorder='big'))
            encrypted_block = tea_encrypt_block(block, key)
            encrypted.extend(encrypted_block[0].to_bytes(4, byteorder='big'))
            encrypted.extend(encrypted_block[1].to_bytes(4, byteorder='big'))

    return bytes(encrypted)


def ecb_mode_decrypt(ciphertext, key):
    decrypted = bytearray()

    for i in range(0, len(ciphertext), 8):
        if i < 80:  # Leave first 10 blocks (80 bytes) unencrypted
            decrypted.extend(ciphertext[i:i + 8])
        else:
            block = (int.from_bytes(ciphertext[i:i + 4], byteorder='big'),
                     int.from_bytes(ciphertext[i + 4:i + 8], byteorder='big'))
            decrypted_block = tea_decrypt_block(block, key)
            decrypted.extend(decrypted_block[0].to_bytes(4, byteorder='big'))
            decrypted.extend(decrypted_block[1].to_bytes(4, byteorder='big'))

    return unpad_plaintext(bytes(decrypted))

def cbc_mode_encrypt(plaintext, key, iv):
    plaintext = pad_plaintext(plaintext)
    encrypted = bytearray()
    previous_block = iv

    for i in range(0, len(plaintext), 8):
        if i < 80:  # Leave first 10 blocks (80 bytes) unencrypted
            encrypted.extend(plaintext[i:i + 8])
            previous_block = plaintext[i:i + 8]
        else:
            block = (int.from_bytes(plaintext[i:i + 4], byteorder='big'),
                     int.from_bytes(plaintext[i + 4:i + 8], byteorder='big'))
            block = (block[0] ^ int.from_bytes(previous_block[:4], byteorder='big'),
                     block[1] ^ int.from_bytes(previous_block[4:], byteorder='big'))
            encrypted_block = tea_encrypt_block(block, key)
            encrypted.extend(encrypted_block[0].to_bytes(4, byteorder='big'))
            encrypted.extend(encrypted_block[1].to_bytes(4, byteorder='big'))
            previous_block = encrypted[-8:]

    return bytes(encrypted)


def cbc_mode_decrypt(ciphertext, key, iv):
    decrypted = bytearray()
    previous_block = iv

    for i in range(0, len(ciphertext), 8):
        if i < 80:  # Leave first 10 blocks (80 bytes) unencrypted
            decrypted.extend(ciphertext[i:i + 8])
            previous_block = ciphertext[i:i + 8]
        else:
            block = (int.from_bytes(ciphertext[i:i + 4], byteorder='big'),
                     int.from_bytes(ciphertext[i + 4:i + 8], byteorder='big'))
            decrypted_block = tea_decrypt_block(block, key)
            decrypted_block = (decrypted_block[0] ^ int.from_bytes(previous_block[:4], byteorder='big'),
                               decrypted_block[1] ^ int.from_bytes(previous_block[4:], byteorder='big'))
            decrypted.extend(decrypted_block[0].to_bytes(4, byteorder='big'))
            decrypted.extend(decrypted_block[1].to_bytes(4, byteorder='big'))
            previous_block = ciphertext[i:i + 8]

    return unpad_plaintext(bytes(decrypted))



- Simple padding and unpadding of plaintext.
  
def pad_plaintext(plaintext):
    padding_len = (8 - len(plaintext) % 8) % 8
    return plaintext + b'\x00' * padding_len


def unpad_plaintext(padded_plaintext):
    return padded_plaintext.rstrip(b'\x00')





	Requirements
- need only Python 3.x


	Files
- “main.py”: Contains the implementation code of the TEA encryption and decryption in ECB and CBC modes.
- “Aqsa.bmp”: The BMP image file to be encrypted and decrypted.

	How to Execute

1. Open PyCharm or any other studio suitable for python code.

2. Run the Script: run main.py by pressing on the green arrow.

3. Inter Inputs:
   
•	Key: Enter 4 32-bit integers in hexadecimal, separated by spaces. 
Example: “0x01234567 0x89abcdef 0xfedcba98 0x76543210”
•	IV: Enter an 8-byte initialization vector in hexadecimal. 
Example: “0123456789abcdef “
•	Plaintext: Enter the plaintext string you want to encrypt.
 Example: 

5. Outputs:
   - The script will print the original plaintext, encrypted data, and decrypted plaintext for both ECB and CBC modes.
     
print("\nOriginal Plaintext:", plaintext.decode())
print("\nEncrypted Data Using ECB:", encrypted_data)
print("\nDecrypted Plaintext Using ECB:", decrypted_plaintext)
print("\nEncrypted Data Using CBC:", encrypted_data2)
print("\nDecrypted Plaintext Using CBC:", decrypted_plaintext2)


   - It will save the original, encrypted, and decrypted BMP images with the following filenames:
     - `original_image.bmp`
     - `encrypted_image_ecb.bmp`
     - `decrypted_image_ecb.bmp`
     - `encrypted_image_cbc.bmp`
     - `decrypted_image_cbc.bmp`
# Read the BMP image file
with open("Aqsa.bmp", "rb") as image_file:
    image_data = image_file.read()

# Save the original image
with open("original_image.bmp", "wb") as original_image_file:
    original_image_file.write(image_data)

print("Original Image saved as: original_image.bmp")

# Save encrypted image (ECB mode)
with open("encrypted_image_ecb.bmp", "wb") as encrypted_image_file:
    encrypted_image_file.write(encrypted_data_ecb)
print("Encrypted Image (ECB mode) saved as: encrypted_image_ecb.bmp")

# Save decrypted image (ECB mode)
with open("decrypted_image_ecb.bmp", "wb") as decrypted_image_file:
    decrypted_image_file.write(decrypted_data_ecb)
print("Decrypted Image (ECB mode) saved as: decrypted_image_ecb.bmp")

# Save encrypted image (CBC mode)
with open("encrypted_image_cbc.bmp", "wb") as encrypted_image_file:
    encrypted_image_file.write(encrypted_data_cbc)
print("Encrypted Image (CBC mode) saved as: encrypted_image_cbc.bmp")

# Save decrypted image (CBC mode)
with open("decrypted_image_cbc.bmp", "wb") as decrypted_image_file:
    decrypted_image_file.write(decrypted_data_cbc)
print("Decrypted Image (CBC mode) saved as: decrypted_image_cbc.bmp")





	Notes
- make sure `Aqsa.bmp` is in the same directory as the script.
 

- The script leaves the first 10 blocks (80 bytes) of data unencrypted so it should be seen unchanged during the procces.

