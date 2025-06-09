import jwt
import time
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

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
    now = int(time.time())
    claims['iat'] = now
    claims['exp'] = now + 3600
    claims['nbf'] = now

    # Optionally add custom claims
    add_custom_claims = input("Do you want to add custom claims (y/n)? ").strip().lower()
    while add_custom_claims == 'y':
        custom_claim_key = input("Enter the custom claim key: ").strip()
        custom_claim_value = input("Enter the custom claim value: ").strip()
        claims[custom_claim_key] = custom_claim_value
        add_custom_claims = input("Do you want to add another custom claim (y/n)? ").strip().lower()

    # Handle signing algorithms
    key_used = None
    public_key = None

    if algorithm in ['HS256', 'HS384', 'HS512']:
        secret = input("Enter the secret key for signing (HMAC): ").strip()
        key_used = secret
        token = jwt.encode(claims, secret, algorithm=algorithm)
        print(f"\nGenerated {algorithm} Token:\n{token}\n")

    elif algorithm in ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']:
        private_key, public_key = generate_rsa_keys()
        private_key_str = private_key.decode()
        public_key_str = public_key.decode()
        key_used = private_key_str
        token = jwt.encode(claims, private_key_str, algorithm=algorithm)
        print(f"\nGenerated {algorithm} Token:\n{token}\n")
        print("Public Key (use this for validation):\n", public_key_str)

    elif algorithm in ['ES256', 'ES384', 'ES512']:
        private_key, public_key = generate_ecdsa_keys()
        private_key_str = private_key.decode()
        public_key_str = public_key.decode()
        key_used = private_key_str
        token = jwt.encode(claims, private_key_str, algorithm=algorithm)
        print(f"\nGenerated {algorithm} Token:\n{token}\n")
        print("Public Key (use this for validation):\n", public_key_str)

    elif algorithm == 'none':
        header = {"alg": "none", "typ": "JWT"}
        segments = [
            base64url_encode(json.dumps(header).encode()),
            base64url_encode(json.dumps(claims).encode()),
            ""
        ]
        token = ".".join(segments)
        print("\nGenerated Insecure Token (alg=none):\n", token)
        key_used = None

    else:
        print("Invalid algorithm choice! Please choose a valid algorithm.")
        return

    # Validate the token immediately
    print("\n--- Token Validation ---")
    try:
        if algorithm == 'none':
            decoded = jwt.decode(token, options={"verify_signature": False})
        elif algorithm in ['HS256', 'HS384', 'HS512']:
            decoded = jwt.decode(token, key_used, algorithms=[algorithm])
        elif algorithm in ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512']:
            decoded = jwt.decode(token, public_key.decode(), algorithms=[algorithm])
        else:
            print("Validation not supported for this algorithm.")
            return
        print("Token is valid. Decoded payload:")
        print(json.dumps(decoded, indent=2))
    except Exception as e:
        print("Token validation failed:", str(e))

if __name__ == "__main__":
    create_jwt_token()