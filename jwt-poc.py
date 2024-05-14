
## Part where we are generating the Private and Public Keys
# ------------------------------------------------------------>

# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa

# def generate_key_pair():
#     # Generate RSA key pair
#     key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048,
#         backend=default_backend()
#     )

#     # Get private key in PEM format
#     private_key_pem = key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=serialization.NoEncryption()  # No encryption for private key
#     )

#     # Get public key in PEM format
#     public_key_pem = key.public_key().public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )

#     return private_key_pem, public_key_pem

# def save_key_to_file(key_data, filename):
#     # Write key data to file
#     with open(filename, "wb") as key_file:
#         key_file.write(key_data)

# # Generate key pair
# private_key_pem, public_key_pem = generate_key_pair()

# Save private key to file
# save_key_to_file(private_key_pem, "private_key.pem")
# print("Private key saved to private_key.pem")

# Save public key to file
# save_key_to_file(public_key_pem, "public_key.pem")
# print("Public key saved to public_key.pem")

# ------------------------------------------------------------>


# Here we are using the Private key to encrypt the data

# import jwt
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization

# def load_private_key():
#     # Load private key from file (in PEM format)
#     with open("private_key.pem", "rb") as key_file:
#         private_key = serialization.load_pem_private_key(
#             key_file.read(),
#             password=None,  # Replace with password if encrypted
#             backend=default_backend()
#         )
#     return private_key

# def create_signed_token(payload):
#     try:
#         # Load private key
#         private_key = load_private_key()

#         # Sign the token using RS256 algorithm
#         token = jwt.encode(payload, private_key, algorithm="RS256")
#         return token.decode()  # Convert bytes to string
#     except Exception as e:
#         print("Error creating signed token:", e)
#         return None

# # Example payload (claims) to be included in the JWT
# payload = {
#     "user_id": 1234,
#     "username": "john_doe",
#     "role": "admin"
# }

# # Create and sign the JWT token
# signed_token = create_signed_token(payload)
# if signed_token:
#     print("Signed Token:", signed_token)
    
    
    
# ------------------------------------------------------------>

    
# token here for example

# eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyX2lkIjoxMjM0LCJ1c2VybmFtZSI6ImpvaG5fZG9lIiwicm9sZSI6ImFkbWluIn0.sP3r9fRnD0SCPPZ3NXyp0qHzRopXoK9kDU5w-KxSZbnCXZoIFQqgcz0Blp5yfQYW5CVSHXQEUBnRcYtXqk0m97nPY_RSo5pdopF-sQEQXvvAl9G3E_gvGz599aj-fSEnt-J81UfVbd9-FuAX9ASgjdCUWbjutA5NvIPLPuPTRz5Zmi1BzAOqbrPQVV4zUKM6lY4HSPfd8uGjuTxcSvi6DvsYj5Mmv-zQVXf7PJeva0kPlzy_NamSlwa-3XBmL8EXKHArJVOcCU6UXqwuXJ5hz4ne_fkHWFVrqa4F315fR4IKW5xb4GNqwKb9Hh4KJkmMjvLVyhK4EqOvG74z2goYMQ


# Now verify the signature using public key


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
