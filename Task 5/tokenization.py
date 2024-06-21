import os
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Initialize database connection
def init_db():
    # Create a new SQLite database or connect to an existing one
    conn = sqlite3.connect('tokenization.db')
    cursor = conn.cursor()
    # Create a table to store tokens and card data if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            card_data TEXT
        )
    ''')
    conn.commit()
    return conn, cursor

# Generate a random token
def generate_token():
    return get_random_bytes(16).hex()

# Encrypt card data using AES
def encrypt_card_data(card_data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(card_data.encode('utf-8'))
    return nonce, ciphertext, tag

# Decrypt card data using AES
def decrypt_card_data(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    card_data = cipher.decrypt_and_verify(ciphertext, tag)
    return card_data.decode('utf-8')

# Tokenize card data
def tokenize_card_data(card_data, key, cursor, conn):
    # Encrypt the card data
    nonce, ciphertext, tag = encrypt_card_data(card_data, key)
    # Generate a token
    token = generate_token()
    # Store the token and encrypted card data in the database
    cursor.execute('INSERT INTO tokens (token, card_data) VALUES (?, ?)', 
                   (token, ciphertext.hex() + ":" + nonce.hex() + ":" + tag.hex()))
    conn.commit()
    return token

# Detokenize to retrieve original card data
def detokenize_card_data(token, key, cursor):
    cursor.execute('SELECT card_data FROM tokens WHERE token = ?', (token,))
    result = cursor.fetchone()
    if result:
        # Extract the encrypted card data components
        ciphertext, nonce, tag = result[0].split(":")
        ciphertext = bytes.fromhex(ciphertext)
        nonce = bytes.fromhex(nonce)
        tag = bytes.fromhex(tag)
        # Decrypt and return the card data
        return decrypt_card_data(nonce, ciphertext, tag, key)
    else:
        raise ValueError("Token not found")

# Main function to demonstrate tokenization and detokenization
def main():
    # Initialize database
    conn, cursor = init_db()
    # Define a key for AES encryption
    key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes long
    
    # Example card data
    card_data = "1234 5678 9012 3456"
    
    # Tokenize the card data
    token = tokenize_card_data(card_data, key, cursor, conn)
    print("Token:", token)
    
    # Detokenize to retrieve the original card data
    original_card_data = detokenize_card_data(token, key, cursor)
    print("Original Card Data:", original_card_data)
    
    # Close the database connection
    conn.close()

if __name__ == "__main__":
    main()
