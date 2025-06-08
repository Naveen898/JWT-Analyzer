import jwt
from jwt import InvalidSignatureError, ExpiredSignatureError, DecodeError
from rich import print

class JWTSignatureVerifier:
    def __init__(self, token, secret):
        self.token = token
        self.secret = secret

    def verify_signature(self):
        try:
            decoded = jwt.decode(
                self.token,
                self.secret,
                algorithms=["HS256"]
            )
            print("\n[green]✅ Signature is valid. Token is authentic.[/green]")
            return decoded
        except InvalidSignatureError:
            print("[red]❌ Invalid signature! Token may have been tampered with.[/red]")
        except ExpiredSignatureError:
            print("[red]❌ Token has expired.[/red]")
        except DecodeError:
            print("[red]❌ Failed to decode JWT. Possibly malformed token.[/red]")
        except Exception as e:
            print(f"[red]❌ Unexpected error: {e}[/red]")
