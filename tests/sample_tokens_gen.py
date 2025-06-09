import jwt
import time
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes as asymmetric_hashes

# Helper function to base64url encode
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# Function to generate RSA keys (Private and Public)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

# Function to generate ECDSA keys (P-256 curve)
def generate_ecdsa_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

# Function to create a JWT with customizable claims and signing algorithms
def create_jwt_token():
    print("Welcome to the JWT Token Generator!")

    # Choose algorithm
    algorithm = input("Enter the signing algorithm (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, none): ").strip()

    # Custom Claims
    claims = {}
    claims['sub'] = input("Enter the 'sub' (subject): ").strip()
    claims['name'] = input("Enter the 'name': ").strip()
    claims['role'] = input("Enter the 'role' (admin/user/guest): ").strip()

    # Registered Claims (Optional)
    claims['iat'] = int(time.time())  # Issued at the current time
    claims['exp'] = int(time.time()) + 3600  # Expires in 1 hour
    claims['nbf'] = int(time.time())  # Not before the current time

    # Optionally add custom claims
    add_custom_claims = input("Do you want to add custom claims (y/n)? ").strip().lower()
    while add_custom_claims == 'y':
        custom_claim_key = input("Enter the custom claim key: ").strip()
        custom_claim_value = input("Enter the custom claim value: ").strip()
        claims[custom_claim_key] = custom_claim_value
        add_custom_claims = input("Do you want to add another custom claim (y/n)? ").strip().lower()

    # Handle signing algorithms

    if algorithm in ['HS256', 'HS384', 'HS512']:  # HMAC-based algorithms
        secret = input("Enter the secret key for signing (HMAC): ").strip()
        token = jwt.encode(claims, secret, algorithm=algorithm)
        print(f"Generated {algorithm} Token:\n", token)

    elif algorithm in ['RS256', 'RS384', 'RS512']:  # RSA-based algorithms
        private_key, public_key = generate_rsa_keys()
        private_key_str = private_key.decode()
        token = jwt.encode(claims, private_key_str, algorithm=algorithm)
        print(f"Generated {algorithm} Token:\n", token)

    elif algorithm in ['ES256', 'ES384', 'ES512']:  # ECDSA-based algorithms
        private_key, public_key = generate_ecdsa_keys()
        private_key_str = private_key.decode()
        token = jwt.encode(claims, private_key_str, algorithm=algorithm)
        print(f"Generated {algorithm} Token:\n", token)

    elif algorithm in ['PS256', 'PS384', 'PS512']:  # RSASSA-PSS algorithms
        private_key, public_key = generate_rsa_keys()
        private_key_str = private_key.decode()
        token = jwt.encode(claims, private_key_str, algorithm=algorithm)
        print(f"Generated {algorithm} Token:\n", token)

    elif algorithm == 'none':  # No signature (unsigned JWT)
        header = {"alg": "none", "typ": "JWT"}
        segments = [
            base64url_encode(json.dumps(header).encode()),
            base64url_encode(json.dumps(claims).encode()),
            ""
        ]
        token = ".".join(segments)
        print("Generated Insecure Token (alg=none):\n", token)

    else:
        print("Invalid algorithm choice! Please choose a valid algorithm.")
        return

if __name__ == "__main__":
    create_jwt_token()
