from analyzer.decoder import JWTDecoder
from analyzer.validator import JWTValidator

if __name__ == "__main__":
    test_jwt = input("Enter JWT: ").strip()

    try:
        decoder = JWTDecoder(test_jwt)
        decoded = decoder.decode()
        decoder.pretty_print()

        validator = JWTValidator(decoded)
        validator.validate()

    except ValueError as e:
        print(f"[red]❌ Error:[/red] {e}")
