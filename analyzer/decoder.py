import base64
import json
from rich import print


class JWTDecoder:
    def __init__(self, token):
        self.token = token
        self.parts = token.split('.')
        self.decoded = {}

    def decode_part(self, part):
        """Base64URL decode with padding fix."""
        padding = '=' * ((4 - len(part) % 4) % 4)
        try:
            return base64.urlsafe_b64decode(part + padding)
        except Exception as e:
            raise ValueError(f"Error decoding base64 part: {e}")

    def decode(self):
        if len(self.parts) != 3:
            raise ValueError("Invalid JWT: Expected 3 parts (header.payload.signature)")

        try:
            header = json.loads(self.decode_part(self.parts[0]))
            payload = json.loads(self.decode_part(self.parts[1]))
            signature = self.parts[2]  # Not decoded, just raw

            self.decoded = {
                "header": header,
                "payload": payload,
                "signature": signature
            }

            return self.decoded
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in JWT: {e}")
        except Exception as e:
            raise ValueError(f"Failed to decode JWT: {e}")

    def pretty_print(self):
        print("[bold blue]\n📘 JWT Header:[/bold blue]")
        print(json.dumps(self.decoded.get("header", {}), indent=2))
        print("\n[bold green]📗 JWT Payload:[/bold green]")
        print(json.dumps(self.decoded.get("payload", {}), indent=2))
        print("\n[bold red]🔐 JWT Signature:[/bold red]")
        print(self.decoded.get("signature", ""))
