import boto3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json

# Initialize AWS clients
kms_client = boto3.client('kms')
secrets_manager_client = boto3.client('secretsmanager')

# Key ID of the AWS KMS key
KMS_KEY_ID = 'alias/your-kms-key-alias'

# Encrypt card data using AES with KMS key for key management
def encrypt_card_data(card_data):
    # Generate a data encryption key (DEK) using KMS
    response = kms_client.generate_data_key(KeyId=KMS_KEY_ID, KeySpec='AES_256')
    dek = response['Plaintext']
    encrypted_dek = response['CiphertextBlob']
    
    # Encrypt the card data using the DEK
    cipher = AES.new(dek, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(card_data.encode('utf-8'))
    
    # Encode nonce, ciphertext, and tag as base64 strings for storage
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    tag_b64 = base64.b64encode(tag).decode('utf-8')
    encrypted_dek_b64 = base64.b64encode(encrypted_dek).decode('utf-8')
    
    return nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64

# Decrypt card data using AES with KMS key for key management
def decrypt_card_data(nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64):
    # Decode base64 strings to bytes
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)
    encrypted_dek = base64.b64decode(encrypted_dek_b64)
    
    # Decrypt the DEK using KMS
    response = kms_client.decrypt(CiphertextBlob=encrypted_dek)
    dek = response['Plaintext']
    
    # Decrypt the card data using the DEK
    cipher = AES.new(dek, AES.MODE_EAX, nonce=nonce)
    card_data = cipher.decrypt_and_verify(ciphertext, tag)
    return card_data.decode('utf-8')

# Store token and encrypted card data in AWS Secrets Manager
def store_token(token, nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64):
    secret_value = {
        'nonce': nonce_b64,
        'ciphertext': ciphertext_b64,
        'tag': tag_b64,
        'encrypted_dek': encrypted_dek_b64
    }
    secrets_manager_client.put_secret_value(
        SecretId=token,
        SecretString=json.dumps(secret_value)
    )

# Retrieve token and encrypted card data from AWS Secrets Manager
def retrieve_token(token):
    response = secrets_manager_client.get_secret_value(SecretId=token)
    secret_value = json.loads(response['SecretString'])
    return (secret_value['nonce'], secret_value['ciphertext'], 
            secret_value['tag'], secret_value['encrypted_dek'])

# Main function to demonstrate cloud integration for tokenization
def main():
    # Example card data
    card_data = "1234 5678 9012 3456"
    
    # Encrypt card data
    nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64 = encrypt_card_data(card_data)
    
    # Generate a token (in this case, using a simple UUID)
    token = generate_token()
    
    # Store the token and encrypted card data in AWS Secrets Manager
    store_token(token, nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64)
    print("Token stored:", token)
    
    # Retrieve the token and encrypted card data from AWS Secrets Manager
    retrieved_nonce, retrieved_ciphertext, retrieved_tag, retrieved_encrypted_dek = retrieve_token(token)
    
    # Decrypt the card data
    decrypted_card_data = decrypt_card_data(retrieved_nonce, retrieved_ciphertext, retrieved_tag, retrieved_encrypted_dek)
    print("Decrypted Card Data:", decrypted_card_data)

if __name__ == "__main__":
    main()
