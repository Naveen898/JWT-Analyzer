import time
from rich import print

class JWTValidator:
    def __init__(self, decoded_token):
        self.header = decoded_token.get("header", {})
        self.payload = decoded_token.get("payload", {})
        self.issues = []

    def validate(self):
        self.check_alg()
        self.check_claims()
        self.report_issues()

    def check_alg(self):
        alg = self.header.get("alg", "")
        if not alg:
            self.issues.append("[yellow]⚠️ 'alg' field is missing in header[/yellow]")
        elif alg.lower() == "none":
            self.issues.append("[red]❌ 'alg: none' is insecure and must be avoided[/red]")
        elif alg.lower().startswith("hs"):
            self.issues.append("[orange1]⚠️ HMAC algorithm used – ensure secure key handling[/orange1]")

    def check_claims(self):
        now = int(time.time())

        # Check exp (expiry)
        exp = self.payload.get("exp")
        if exp:
            if exp < now:
                self.issues.append(f"[red]❌ Token is expired (exp: {exp}, now: {now})[/red]")
        else:
            self.issues.append("[yellow]⚠️ Missing 'exp' (expiry) claim[/yellow]")

        # Check iat (issued at)
        iat = self.payload.get("iat")
        if iat:
            if iat > now:
                self.issues.append(f"[red]❌ 'iat' is in the future (iat: {iat}, now: {now})[/red]")
        else:
            self.issues.append("[yellow]⚠️ Missing 'iat' (issued at) claim[/yellow]")

        # Check nbf (not before)
            # Check nbf (not before)
            nbf = self.payload.get("nbf")
            if nbf is not None:
                if nbf > now:
                    self.issues.append(f"[red]❌ Token is not valid yet (nbf: {nbf}, now: {now})[/red]")
            else:
                self.issues.append("[yellow]⚠️ Missing 'nbf' (not before) claim[/yellow]")

    def report_issues(self):
        print("\n[bold magenta]🔍 Validation Results:[/bold magenta]")
        if not self.issues:
            print("[green]✅ No issues found. Token appears valid.[/green]")
        else:
            for issue in self.issues:
                print(issue)
