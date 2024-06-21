# Credit/Debit Card Encryption and Tokenization System

This project is a comprehensive system for encrypting, decrypting, tokenizing, and securely storing credit/debit card data. The system uses Flask for the web server, AES for encryption, and integrates with AWS services for secure storage.

## Project Structure
project_root/
│
├── app.py
├── encrypt_decrypt.py
├── tokenization.py
├── cloud_integration.py
├── access_control.py
├── test_encrypt_decrypt.py
├── test_tokenization.py
├── test_cloud_integration.py
└── requirements.txt


## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/yourrepository.git
   cd yourrepository

Create and Activate a Virtual Environment:
```python -m venv venv```
```source venv/bin/activate   # On Windows, use `venv\Scripts\activate```

Install Dependencies:
```pip install -r requirements.txt```


#Running the Application
1) Run the Flask App:
```python app.py```
2) The application will start running on http://localhost:5000.

Endpoints
Login
URL: /login
Method: POST
Description: Authenticates a user and provides a JWT token.
Example:
```curl -u user:password http://localhost:5000/login```

Encrypt Card Data
URL: /encrypt
Method: POST
Description: Encrypts card data.
Request Body
```{
  "card_data": "1234 5678 9012 3456"
}
```
Decrypt Card Data
URL: /decrypt
Method: POST
Description: Decrypts card data.
Request Body:
```{
  "nonce": "...",
  "ciphertext": "...",
  "tag": "...",
  "key": "..."
}
```

Tokenize Card Data
URL: /tokenize
Method: POST
Description: Tokenizes card data.
Request Body:
json

```{
  "card_data": "1234 5678 9012 3456"
}
```
Detokenize Card Data
URL: /detokenize
Method: POST
Description: Detokenizes card data.
Request Body:
json

```{
  "token": "...",
  "key": "..."
}
```
Cloud Encrypt Card Data
URL: /cloud_encrypt
Method: POST
Description: Encrypts card data and stores it securely in the cloud.
Request Body:
json

```{
  "card_data": "1234 5678 9012 3456"
}
```
Cloud Decrypt Card Data
URL: /cloud_decrypt
Method: POST
Description: Decrypts card data stored in the cloud.
Request Body:
json
```{
  "nonce": "...",
  "ciphertext": "...",
  "tag": "...",
  "encrypted_dek": "..."
}
```
Securely Store Tokenized Data
URL: /secure-token
Method: POST
Description: Stores tokenized data securely.
Headers: x-access-token: your_jwt_token
Request Body:
json

```{
  "card_data": "1234 5678 9012 3456"
}
```
Securely Retrieve Tokenized Data
URL: /secure-retrieve
Method: POST
Description: Retrieves and decrypts tokenized data securely.
Headers: x-access-token: your_jwt_token
Request Body:
json

```{
  "token": "..."
}
```
Testing
This project includes unit tests to verify the functionality of encryption, tokenization, and cloud integration.

Run Encryption/Decryption Tests:

```python test_encrypt_decrypt.py```

Run Tokenization Tests:

```python test_tokenization.py```

Run Cloud Integration Tests:

```python test_cloud_integration.py```
