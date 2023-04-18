import base64
from Crypto.Cipher import AES

def encrypt_video(video_path, key):
    with open(video_path, 'rb') as f:
        video_data = f.read()
    encoded_key = key.encode('utf-8')
    # pad key to make it a multiple of 16 bytes (128 bits)
    padded_key = encoded_key + b'\0' * (16 - len(encoded_key) % 16)
    # create AES cipher with 128-bit key in CBC mode
    cipher = AES.new(padded_key, AES.MODE_CBC, iv=b'1234567890123456')
    # pad video data to make it a multiple of 16 bytes (128 bits)
    padded_video_data = video_data + b'\0' * (16 - len(video_data) % 16)
    # encrypt video data with the key
    encrypted_video_data = cipher.encrypt(padded_video_data)
    # encode the encrypted video data with base64
    encoded_encrypted_video_data = base64.b64encode(encrypted_video_data)
    # write the encoded encrypted video data to a new file
    with open(video_path + '.enc', 'wb') as f:
        f.write(encoded_encrypted_video_data)

def decrypt_video(encrypted_video_path, key):
    with open(encrypted_video_path, 'rb') as f:
        encoded_encrypted_video_data = f.read()
    encoded_key = key.encode('utf-8')
    # pad key to make it a multiple of 16 bytes (128 bits)
    padded_key = encoded_key + b'\0' * (16 - len(encoded_key) % 16)
    # create AES cipher with 128-bit key in CBC mode
    cipher = AES.new(padded_key, AES.MODE_CBC, iv=b'1234567890123456')
    # decode the encoded encrypted video data from base64
    encrypted_video_data = base64.b64decode(encoded_encrypted_video_data)
    # decrypt the encrypted video data with the key
    decrypted_video_data = cipher.decrypt(encrypted_video_data)
    # remove padding from decrypted video data
    unpadded_decrypted_video_data = decrypted_video_data.rstrip(b'\0')
    # write the decrypted video data to a new file
    decrypted_video_path = encrypted_video_path[:-4] + '_decrypted' + encrypted_video_path[-4:]
    with open(decrypted_video_path, 'wb') as f:
        f.write(unpadded_decrypted_video_data)
    return decrypted_video_path

def read_decrypted_file(decrypted_file_path):
    with open(decrypted_file_path, 'rb') as f:
        decrypted_data = f.read()
    return decrypted_data

# encrypt the video
encrypt_video('background.mp4', 'mysecretkey')

