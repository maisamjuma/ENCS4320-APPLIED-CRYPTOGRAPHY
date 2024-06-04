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


def pad_plaintext(plaintext):
    padding_len = (8 - len(plaintext) % 8) % 8
    return plaintext + b'\x00' * padding_len


def unpad_plaintext(padded_plaintext):
    return padded_plaintext.rstrip(b'\x00')


def main():
    key = tuple(int(x, 16) for x in input("Enter the key (4 32-bit integers in hexadecimal, separated by spaces): ").split())
    iv = bytes.fromhex(input("Enter the IV (8 bytes in hexadecimal): "))
    plaintext = input("Enter the plaintext: ").encode()

    print("\nOriginal Plaintext:", plaintext.decode())

    # ECB mode encryption and decryption
    encrypted_data = ecb_mode_encrypt(plaintext, key)
    decrypted_data = ecb_mode_decrypt(encrypted_data, key)

    print("\nEncrypted Data Using ECB:", encrypted_data)
    decrypted_plaintext = decrypted_data.decode()
    print("\nDecrypted Plaintext Using ECB:", decrypted_plaintext)

    # CBC mode encryption and decryption
    encrypted_data2 = cbc_mode_encrypt(plaintext, key, iv)
    decrypted_data2 = cbc_mode_decrypt(encrypted_data2, key, iv)

    print("\nEncrypted Data Using CBC:", encrypted_data2)
    decrypted_plaintext2 = decrypted_data2.decode()
    print("\nDecrypted Plaintext Using CBC:", decrypted_plaintext2)

    # Verify if decrypted plaintext matches original plaintext
    if plaintext == decrypted_plaintext.encode():
        print("\nSuccess: Decrypted plaintext matches the original plaintext using ECB mode!")
    else:
        print("\nError: Decrypted plaintext does not match the original plaintext using ECB mode.")

    if plaintext == decrypted_plaintext2.encode():
        print("\nSuccess: Decrypted plaintext matches the original plaintext using CBC mode!")
    else:
        print("\nError: Decrypted plaintext does not match the original plaintext using CBC mode.")

    # Read the BMP image file
    with open("Aqsa.bmp", "rb") as image_file:
        image_data = image_file.read()

    # Save the original image
    with open("original_image.bmp", "wb") as original_image_file:
        original_image_file.write(image_data)

    print("Original Image saved as: original_image.bmp")

    # ECB mode encryption and decryption
    encrypted_data_ecb = ecb_mode_encrypt(image_data, key)
    decrypted_data_ecb = ecb_mode_decrypt(encrypted_data_ecb, key)

    # Save encrypted image (ECB mode)
    with open("encrypted_image_ecb.bmp", "wb") as encrypted_image_file:
        encrypted_image_file.write(encrypted_data_ecb)
    print("Encrypted Image (ECB mode) saved as: encrypted_image_ecb.bmp")

    # Save decrypted image (ECB mode)
    with open("decrypted_image_ecb.bmp", "wb") as decrypted_image_file:
        decrypted_image_file.write(decrypted_data_ecb)
    print("Decrypted Image (ECB mode) saved as: decrypted_image_ecb.bmp")

    # CBC mode encryption and decryption
    encrypted_data_cbc = cbc_mode_encrypt(image_data, key, iv)
    decrypted_data_cbc = cbc_mode_decrypt(encrypted_data_cbc, key, iv)

    # Save encrypted image (CBC mode)
    with open("encrypted_image_cbc.bmp", "wb") as encrypted_image_file:
        encrypted_image_file.write(encrypted_data_cbc)
    print("Encrypted Image (CBC mode) saved as: encrypted_image_cbc.bmp")

    # Save decrypted image (CBC mode)
    with open("decrypted_image_cbc.bmp", "wb") as decrypted_image_file:
        decrypted_image_file.write(decrypted_data_cbc)
    print("Decrypted Image (CBC mode) saved as: decrypted_image_cbc.bmp")

    print("Encryption and decryption completed successfully.")

if __name__ == "__main__":
    main()
