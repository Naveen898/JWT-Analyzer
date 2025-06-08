import jwt
from jwt.exceptions import InvalidSignatureError, DecodeError
from rich import print

# Simulated token database to detect replays
USED_TOKENS = set()

class JWTSecurity:
    def __init__(self, jwt_token, header, payload):
        self.jwt_token = jwt_token
        self.header = header
        self.payload = payload

    def verify_signature(self, secret_key):
        alg = self.header.get("alg", "")
        try:
            jwt.decode(
                self.jwt_token,
                secret_key,
                algorithms=[alg]
            )
            print("[green]✅ Signature is valid[/green]")
            return True
        except InvalidSignatureError:
            print("[red]❌ Invalid signature! Token may have been tampered with.[/red]")
            return False
        except DecodeError:
            print("[red]❌ Failed to decode token. Check structure or key.[/red]")
            return False
        except Exception as e:
            print(f"[red]❌ Signature verification error: {e}[/red]")
            return False

    def check_replay(self):
        if self.jwt_token in USED_TOKENS:
            print("[red]❌ Token Replay Detected! This token has been used before.[/red]")
        else:
            print("[green]🆗 Token has not been seen before – recording use.[/green]")
            USED_TOKENS.add(self.jwt_token)
