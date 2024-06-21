import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)

# Secret key to encode and decode JWT tokens
SECRET_KEY = 'your_secret_key'

# Generate an access token
def generate_access_token(user_id, expiration_minutes=30):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration_minutes)
    token = jwt.encode({'user_id': user_id, 'exp': expiration}, SECRET_KEY, algorithm='HS256')
    return token

# Middleware to verify the access token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check if token is provided in the headers
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            # Decode the token
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(user_id, *args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    # Dummy user authentication
    auth = request.authorization
    if auth and auth.username == 'user' and auth.password == 'password':
        token = generate_access_token(user_id=1)
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/secure-data', methods=['GET'])
@token_required
def secure_data(user_id):
    # Only accessible if a valid token is provided
    return jsonify({'message': 'This is secure data accessible only with a valid token!', 'user_id': user_id})

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
