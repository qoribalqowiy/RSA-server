from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from flask_cors import CORS  # Import CORS module

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Generate a new RSA key pair
key = RSA.generate(2048)

# Export the public key in PEM format
public_key = key.publickey().export_key(format='PEM')
private_key = key.export_key(format='PEM')

print(public_key.decode())
print(private_key.decode())




# Function for RSA encryption
def encrypt_message(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode('utf-8')

# Function for RSA decryption
def decrypt_message(encrypted_message, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message)).decode('utf-8')
    return decrypted_message

@app.route('/')
def home():
    return 'Hello from Flask on Vercel!'

# API for encryption
@app.route('/api/encrypt', methods=['POST'])  # Accepting only POST method
def encrypt():
    data = request.json
    message = data['message']
    encrypted_message = encrypt_message(message, public_key)
    return jsonify({'encrypted_message': encrypted_message})

# API for decryption
@app.route('/api/decrypt', methods=['POST'])  # Accepting only POST method
def decrypt():
    data = request.json
    encrypted_message = data['encrypted_message']
    decrypted_message = decrypt_message(encrypted_message, private_key)
    return jsonify({'decrypted_message': decrypted_message})

if __name__ == '_main_':
    app.run(debug=True)