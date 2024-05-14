# Asymmetric JWT Flow

This document explains the flow of asymmetric JSON Web Token (JWT), which leverages asymmetric cryptography for secure data transmission and verification.

## Key Generation

1. **Private Key Generation**:
   - The issuer (server-side) generates an RSA key pair consisting of a private key and a corresponding public key.
   - The private key is securely kept on the issuer's side and is used for signing JWT tokens.

2. **Public Key Distribution**:
   - The public key is shared with consumers (client-side) who need to verify JWT tokens.
   - Public key distribution methods include embedding in the JWT, using well-known locations, or providing out-of-band.

## JWT Token Creation (Issuance)

3. **Payload Creation**:
   - The issuer creates a JSON payload (claims) containing the data to be transmitted securely within the JWT.
   - Common claims include user ID, username, roles, and other relevant information.

4. **Token Signing**:
   - Using the private key, the issuer signs the JWT token by combining the base64-encoded header, payload, and specified cryptographic algorithm (e.g., RS256).
   - The resulting signature is appended to the header and payload to form the complete JWT.

## JWT Token Transmission

5. **Token Distribution**:
   - The signed JWT token is transmitted to consumers (client-side) through secure channels such as HTTP headers or cookies.

## JWT Token Verification

6. **Token Decoding**:
   - Consumers decode the received JWT token to extract the header, payload, and signature components.

7. **Signature Verification**:
   - Using the shared public key, consumers verify the signature of the JWT token.
   - The public key ensures that the signature matches the content (header and payload) of the JWT.
   - If the signature verification is successful, consumers can trust the data contained in the payload.

## Token Usage and Access Control

8. **Access Control**:
   - Consumers use the decoded and verified JWT payload to authorize and grant access to resources based on the contained claims.
   - Claims such as user roles or permissions determine the level of access granted by the consumer.

## Benefits of Asymmetric JWT

- **Enhanced Security**:
  - No need to share a secret key between parties.
  - Public key distribution enables secure verification of JWT tokens.

- **Non-Repudiation**:
  - The issuer cannot deny signing the JWT token (provides proof of origin).

- **Scalability and Interoperability**:
  - Supports secure communication between different systems and platforms.

## Requirements

- Python 3.x
- `cryptography` library (install using `pip install cryptography`)

## Code

### RSA Key Pair Generation Using Python and cryptography Library

- This Python script demonstrates how to generate an RSA key pair (private and public keys) using the `cryptography` library.


```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key_pair():
    # Generate RSA key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get private key in PEM format
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # No encryption for private key
    )

    # Get public key in PEM format
    public_key_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

def save_key_to_file(key_data, filename):
    # Write key data to file
    with open(filename, "wb") as key_file:
        key_file.write(key_data)

# Generate key pair
private_key_pem, public_key_pem = generate_key_pair()

# Save private key to file
save_key_to_file(private_key_pem, "private_key.pem")
print("Private key saved to private_key.pem")

# Save public key to file
save_key_to_file(public_key_pem, "public_key.pem")
print("Public key saved to public_key.pem")
```

## Generation of token using and sign of token using private key

- The resulting signed_token is a string representing the JWT with a digital signature created using the private key. This token can be shared and transmitted securely. Consumers can then use the corresponding public key to verify the authenticity and integrity of the token

```python


import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_private_key():
    # Load private key from file (in PEM format)
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Replace with password if encrypted
            backend=default_backend()
        )
    return private_key

def create_signed_token(payload):
    try:
        # Load private key
        private_key = load_private_key()

        # Sign the token using RS256 algorithm
        token = jwt.encode(payload, private_key, algorithm="RS256")
        return token.decode()  # Convert bytes to string
    except Exception as e:
        print("Error creating signed token:", e)
        return None

# Example payload (claims) to be included in the JWT
payload = {
    "user_id": 1234,
    "username": "john_doe",
    "role": "admin"
}

# Create and sign the JWT token
signed_token = create_signed_token(payload)
if signed_token:
    print("Signed Token:", signed_token)
    
    
```

## Now verify the signature using public key

```python

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_public_key():
    # Load public key from file (in PEM format)
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def verify_token_signature(token):
    try:
        # Load public key
        public_key = load_public_key()

        # Verify the token signature using the public key
        decoded_payload = jwt.decode(token, public_key, algorithms=["RS256"])
        return decoded_payload
    except:
        return None

# Example JWT token (shared token)
shared_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyX2lkIjoxMjM0LCJ1c2VybmFtZSI6ImpvaG5fZG9lIiwicm9sZSI6ImFkbWluIn0.sP3r9fRnD0SCPPZ3NXyp0qHzRopXoK9kDU5w-KxSZbnCXZoIFQqgcz0Blp5yfQYW5CVSHXQEUBnRcYtXqk0m97nPY_RSo5pdopF-sQEQXvvAl9G3E_gvGz599aj-fSEnt-J81UfVbd9-FuAX9ASgjdCUWbjutA5NvIPLPuPTRz5Zmi1BzAOqbrPQVV4zUKM6lY4HSPfd8uGjuTxcSvi6DvsYj5Mmv-zQVXf7PJeva0kPlzy_NamSlwa-3XBmL8EXKHArJVOcCU6UXqwuXJ5hz4ne_fkHWFVrqa4F315fR4IKW5xb4GNqwKb9Hh4KJkmMjvLVyhK4EqOvG74z2goYMQ"

# Verify the signature of the shared token using the public key
decoded_payload = verify_token_signature(shared_token)
if decoded_payload:
    print("Verified Payload:", decoded_payload)
else:
    print("Token verification failed.")


```



---
