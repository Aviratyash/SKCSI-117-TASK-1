import unittest
from Crypto.Random import get_random_bytes
from tokenization import tokenize_card_data, detokenize_card_data, init_db

class TestTokenization(unittest.TestCase):
    def setUp(self):
        # Set up key and example card data for testing
        self.key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes long
        self.card_data = "1234 5678 9012 3456"
        # Initialize database for tokenization tests
        self.conn, self.cursor = init_db()

    def test_tokenize_detokenize(self):
        # Tokenize the card data
        token = tokenize_card_data(self.card_data, self.key, self.cursor, self.conn)
        # Detokenize to retrieve the original card data
        original_card_data = detokenize_card_data(token, self.key, self.cursor)
        # Verify that the detokenized data matches the original card data
        self.assertEqual(self.card_data, original_card_data)

    def tearDown(self):
        # Close the database connection after tests
        self.conn.close()

if __name__ == '__main__':
    unittest.main()
