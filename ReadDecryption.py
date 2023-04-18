# import necessary modules
from Crypto.Cipher import AES
import base64

def decrypt_file(encrypted_file_path, key):
    # open the encrypted file and read its contents
    with open(encrypted_file_path, 'rb') as f:
        encoded_encrypted_data = f.read()

    # decode the encoded encrypted data from base64
    encrypted_data = base64.b64decode(encoded_encrypted_data)
    print("ENRYPTED DATA ------->")
    print(encrypted_data)
    print(" ")

    # create AES cipher with 128-bit key in CBC mode
    encoded_key = key.encode('utf-8')
    padded_key = encoded_key + b'\0' * (16 - len(encoded_key) % 16)
    cipher = AES.new(padded_key, AES.MODE_CBC, iv=b'1234567890123456')

    # decrypt the encrypted data with the key
    decrypted_data = cipher.decrypt(encrypted_data)

    # remove padding from decrypted data
    unpadded_decrypted_data = decrypted_data.rstrip(b'\0')

    # return the decrypted data
    return unpadded_decrypted_data

# define the encrypted file path and decryption key
encrypted_file_path = 'background.mp4.enc'
decryption_key = 'mysecretkey'


# decrypt the file
decrypted_data = decrypt_file(encrypted_file_path, decryption_key)
# print the first 10 bytes of the decrypted data
print("DECRYPTED DATA ------->")

print(decrypted_data[:10])

# write the decrypted data to a new file
with open('background.mp4.dec', 'wb') as f:
    f.write(decrypted_data)

# read the decrypted file
with open('background.mp4.dec', 'rb') as f:
    decrypted_text = f.read()

print(decrypted_text)


