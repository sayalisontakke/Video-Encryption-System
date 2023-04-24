import base64
from Crypto.Cipher import AES
from tkinter import *
from tkinter import filedialog

# Function to handle file upload button click
def browse_file():
    file_path = filedialog.askopenfilename()
    input_box.delete(0, END)
    input_box.insert(END, file_path)

# Function to handle encryption button click
def encrypt():
    video_path = input_box.get()
    key = key_box.get()
    try:
        encrypted_video_path = encrypt_video(video_path, key)
        result_box.insert(END, f"Video encrypted successfully! Encrypted file saved as background.mp4.enc \n")
    except Exception as e:
        result_box.insert(END, f"Error occurred during encryption: {str(e)}\n")

# Function to handle decryption button click
def decrypt():
    encrypted_video_path = input_box.get()
    key = key_box.get()
    try:
        if check_key(key):
            decrypted_video_path = decrypt_video(encrypted_video_path, key)
            if decrypted_video_path:
                result_box.insert(END, f"Video decrypted successfully! Decrypted file saved as: {decrypted_video_path}\n")
        else:
            key = key_box.delete(0, END)
            result_box.insert(END, "Invalid key entered! Please enter the correct key.\n")
    except ValueError:
        result_box.insert(END, "Wrong key entered! Video decryption failed.\n")
    except FileNotFoundError:
        result_box.insert(END, "File not found! Video decryption failed.\n")

# Function to check if key is valid
def check_key(key):
    expected_key = "123" # change this to your expected key
    return key == expected_key

# Function to encrypt video file
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

# Function to decrypt video file
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
    decrypted_video_path = encrypted_video_path[:-4] + '_decrypted' + '.mp4'
    with open(decrypted_video_path, 'wb') as f:
        f.write(unpadded_decrypted_video_data)
    return decrypted_video_path


# Create Tkinter window
root = Tk()
root.title("Video Encryption")
root.geometry("700x400")

# Create input box for file path
input_box = Entry(root, width=50)
input_box.pack(pady=10)

# Create "Browse" button
browse_button = Button(root, text="Browse", command=browse_file)
browse_button.pack()

# Create input box for encryption/decryption key
key_label = Label(root, text="Encryption/Decryption Key:")
key_label.pack()
key_box = Entry(root, width=50, show="*")
key_box.pack(pady=10)

# Create "Encrypt" button
encrypt_button = Button(root, text="Encrypt", command=encrypt)
encrypt_button.pack()

# Create "Decrypt" button
decrypt_button = Button(root, text="Decrypt", command=decrypt)
decrypt_button.pack()

# Create result box for displaying messages
result_box = Text(root, height=5, width=50)
result_box.pack(pady=10)

# Run Tkinter event loop
root.mainloop()
