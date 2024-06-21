from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_card_data(card_data, key):
    """
    Encrypts card data using AES encryption.
    
    :param card_data: The card data to encrypt.
    :param key: The encryption key.
    :return: A tuple of nonce, ciphertext, and tag, all encoded in base64.
    """
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(card_data.encode('utf-8'))
    
    # Encode the nonce, ciphertext, and tag as base64 strings
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    tag_b64 = base64.b64encode(tag).decode('utf-8')
    
    return nonce_b64, ciphertext_b64, tag_b64

def decrypt_card_data(nonce_b64, ciphertext_b64, tag_b64, key):
    """
    Decrypts card data using AES encryption.
    
    :param nonce_b64: The base64 encoded nonce.
    :param ciphertext_b64: The base64 encoded ciphertext.
    :param tag_b64: The base64 encoded tag.
    :param key: The decryption key.
    :return: The decrypted card data as a string.
    """
    # Decode the base64 encoded strings to bytes
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)
    
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    card_data = cipher.decrypt_and_verify(ciphertext, tag)
    
    return card_data.decode('utf-8')

def main():
    # Example card data
    card_data = "1234 5678 9012 3456"
    # Generate a random key for AES encryption
    key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes long
    
    # Encrypt the card data
    nonce_b64, ciphertext_b64, tag_b64 = encrypt_card_data(card_data, key)
    print("Encrypted Data:")
    print("Nonce:", nonce_b64)
    print("Ciphertext:", ciphertext_b64)
    print("Tag:", tag_b64)
    
    # Decrypt the card data
    decrypted_data = decrypt_card_data(nonce_b64, ciphertext_b64, tag_b64, key)
    print("\nDecrypted Data:")
    print(decrypted_data)

if __name__ == "__main__":
    main()
