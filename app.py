from flask import Flask, render_template, request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

app = Flask(__name__)

# Load RSA keys
with open("private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

# AES key (must be 16, 24, or 32 bytes)
AES_KEY = b'ThisIsA16ByteKey'  # Example: 16 bytes

# RSA encryption
def encrypt_rsa(message):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

# RSA decryption
def decrypt_rsa(encrypted_b64):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_b64))
    return decrypted.decode()

# AES encryption
def encrypt_aes(message):
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

# AES decryption
def decrypt_aes(encrypted_b64):
    encrypted = base64.b64decode(encrypted_b64)
    iv, ciphertext = encrypted[:16], encrypted[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

@app.route('/', methods=["GET", "POST"])
def index():
    if request.method == "POST":
        message = request.form["message"]
        method = request.form["method"]
        try:
            if method == "RSA":
                encrypted = encrypt_rsa(message)
                decrypted = decrypt_rsa(encrypted)
            elif method == "AES":
                encrypted = encrypt_aes(message)
                decrypted = decrypt_aes(encrypted)
            else:
                encrypted = decrypted = "Invalid encryption method selected."
        except Exception as e:
            encrypted = "Error during encryption"
            decrypted = f"Error: {str(e)}"
        return render_template("index.html",
                               original=message,
                               encrypted=encrypted,
                               decrypted=decrypted,
                               method=method)
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True)
