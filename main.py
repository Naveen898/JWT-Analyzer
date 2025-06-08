from analyzer.decoder import JWTDecoder
from analyzer.validator import JWTValidator
from analyzer.signature_verifier import JWTSignatureVerifier
from rich import print

def main():
    token = input("Enter JWT: ").strip()
    
    # 1. Decode JWT
    decoder = JWTDecoder(token)
    header, payload, signature = decoder.decode()

    if header is None or payload is None:
        print("[red]❌ Failed to decode JWT. Exiting...[/red]")
        return

    # 2. Validate JWT claims
    decoded_token = {
    "header": header,
    "payload": payload
    }
    validator = JWTValidator(decoded_token)


    # 3. Ask to verify signature
    verify = input("\n🔐 Do you want to verify the JWT signature? (yes/no): ").strip().lower()
    if verify in ("yes", "y"):
        secret = input("🔑 Enter the secret key for signature verification: ").strip()
        verifier = JWTSignatureVerifier(token, secret)
        verifier.verify_signature()

if __name__ == "__main__":
    main()
