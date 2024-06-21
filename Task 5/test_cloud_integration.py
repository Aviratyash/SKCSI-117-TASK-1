import unittest
from moto import mock_kms, mock_secretsmanager
import boto3
import json
from cloud_integration import encrypt_card_data, decrypt_card_data, store_token, retrieve_token, generate_token

class TestCloudIntegration(unittest.TestCase):
    def setUp(self):
        # Start mocks for KMS and Secrets Manager
        self.kms_mock = mock_kms()
        self.kms_mock.start()
        self.secretsmanager_mock = mock_secretsmanager()
        self.secretsmanager_mock.start()
        
        # Create a KMS client and generate a test key
        self.kms_client = boto3.client('kms', region_name='us-east-1')
        self.kms_key_id = self.kms_client.create_key()['KeyMetadata']['KeyId']
        
        # Update cloud_integration.py to use the mock KMS key ID
        global KMS_KEY_ID
        KMS_KEY_ID = self.kms_key_id
        
        # Create a Secrets Manager client
        self.secrets_manager_client = boto3.client('secretsmanager', region_name='us-east-1')
        
        # Example card data
        self.card_data = "1234 5678 9012 3456"

    def test_encrypt_decrypt(self):
        # Encrypt the card data
        nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64 = encrypt_card_data(self.card_data)
        # Decrypt the card data
        decrypted_data = decrypt_card_data(nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64)
        # Verify that the decrypted data matches the original card data
        self.assertEqual(self.card_data, decrypted_data)

    def test_store_retrieve_token(self):
        # Encrypt the card data
        nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64 = encrypt_card_data(self.card_data)
        # Generate a token
        token = generate_token()
        # Store the token and encrypted card data in Secrets Manager
        store_token(token, nonce_b64, ciphertext_b64, tag_b64, encrypted_dek_b64)
        # Retrieve the token and encrypted card data from Secrets Manager
        retrieved_nonce, retrieved_ciphertext, retrieved_tag, retrieved_encrypted_dek = retrieve_token(token)
        # Decrypt the card data
        decrypted_data = decrypt_card_data(retrieved_nonce, retrieved_ciphertext, retrieved_tag, retrieved_encrypted_dek)
        # Verify that the decrypted data matches the original card data
        self.assertEqual(self.card_data, decrypted_data)

    def tearDown(self):
        # Stop mocks for KMS and Secrets Manager
        self.kms_mock.stop()
        self.secretsmanager_mock.stop()

if __name__ == '__main__':
    unittest.main()
