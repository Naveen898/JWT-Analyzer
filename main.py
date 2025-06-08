from analyzer.decoder import JWTDecoder
from analyzer.validator import JWTValidator
from analyzer.security import JWTSecurity
from rich import print

def main():
    jwt_input = input("Enter JWT: ").strip()
    
    decoder = JWTDecoder(jwt_input)
    try:
        decoded = decoder.decode()
    except Exception as e:
        print(f"[red]❌ {e}[/red]")
        return

    header = decoded.get("header", {})
    payload = decoded.get("payload", {})
    signature = decoded.get("signature", "")

    # Display decoded sections
    decoder.pretty_print()

    # Run claim validation
    validator = JWTValidator({
        "header": header,
        "payload": payload
    })
    validator.validate()

    # Signature verification + replay detection
    verify = input("\n🔐 Do you want to verify the JWT signature? (yes/no): ").strip().lower()
    if verify in ("yes", "y"):
        secret = input("🔑 Enter the secret key for signature verification: ").strip()
        security = JWTSecurity(jwt_input, header, payload)
        if security.verify_signature(secret):
            security.check_replay()

if __name__ == "__main__":
    main()