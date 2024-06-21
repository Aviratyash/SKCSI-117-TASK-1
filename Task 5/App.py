from flask import Flask, request, jsonify
from encrypt_decrypt import encrypt_card_data, decrypt_card_data
from tokenization import tokenize_card_data, detokenize_card_data, init_db
from cloud_integration import store_token, retrieve_token, generate_token, encrypt_card_data as cloud_encrypt, decrypt_card_data as cloud_decrypt
from access_control import token_required, generate_access_token
import sqlite3
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# Initialize database for tokenization
conn, cursor = init_db()

@app.route('/encrypt', methods=['POST'])
def encrypt():
    card_data = request.json.get('card_data')
    key = get_random_bytes(16)
    nonce_b64, ciphertext_b64, tag_b64 = encrypt_card_data(card_data, key)
    return jsonify({
        'nonce': nonce_b64,
        'ciphertext': ciphertext_b64,
        'tag': tag_b64
    })

@app.route('/decrypt', methods=['POST'])
def decrypt():
    nonce_b64 = request.json.get('nonce')
    ciphertext_b64 = request.json.get('ciphertext')
    tag_b64 = request.json.get('tag')
    key = request.json.get('key').encode('utf-8')
    decrypted_data = decrypt_card_data(nonce_b64, ciphertext_b64, tag_b64, key)
    return jsonify({'decrypted_data': decrypted_data})

@app.route('/tokenize', methods=['POST'])
def tokenize():
    card_data = request.json.get('card_data')
    key = get_random_bytes(16)
    token = tokenize_card_data(card_data, key, cursor, conn)
    return jsonify({'token': token})

@app.route('/detokenize', methods=['POST'])
def detokenize():
    token = request.json.get('token')
    key = request.json.get('key').encode('utf-8')
    card_data = detokenize_card_data(token, key, cursor)
    return jsonify({'card_data': card_data})

@app.route('/cloud_encrypt', methods=['POST'])
def cloud_encrypt_data():
    card_data = request.json.get('card_data')
    nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64 = cloud_encrypt(card_data)
    return jsonify({
        'nonce': nonce_b64,
        'ciphertext': ciphertext_b64,
        'tag': tag_b64,
        'encrypted_dek': encrypted_dek_b64
    })

@app.route('/cloud_decrypt', methods=['POST'])
def cloud_decrypt_data():
    nonce_b64 = request.json.get('nonce')
    ciphertext_b64 = request.json.get('ciphertext')
    tag_b64 = request.json.get('tag')
    encrypted_dek_b64 = request.json.get('encrypted_dek')
    decrypted_data = cloud_decrypt(nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64)
    return jsonify({'decrypted_data': decrypted_data})

@app.route('/secure-token', methods=['POST'])
@token_required
def secure_store_token(user_id):
    card_data = request.json.get('card_data')
    nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64 = cloud_encrypt(card_data)
    token = generate_token()
    store_token(token, nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64)
    return jsonify({'token': token})

@app.route('/secure-retrieve', methods=['POST'])
@token_required
def secure_retrieve_token(user_id):
    token = request.json.get('token')
    retrieved_nonce, retrieved_ciphertext, retrieved_tag, retrieved_encrypted_dek = retrieve_token(token)
    decrypted_data = cloud_decrypt(retrieved_nonce, retrieved_ciphertext, retrieved_tag, retrieved_encrypted_dek)
    return jsonify({'decrypted_data': decrypted_data})

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if auth and auth.username == 'user' and auth.password == 'password':
        token = generate_access_token(user_id=1)
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials!'}), 401

if __name__ == '__main__':
    app.run(debug=True)
