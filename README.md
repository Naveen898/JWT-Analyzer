# 🛡️ JWT Analyzer – Token Abuse Detector

A Python-based tool to decode, validate, and assess JSON Web Tokens (JWTs) for common misconfigurations and security issues. Comes with a CLI utility, Flask API, and an interactive JWT token generator.

---

## 📦 Features

- ✅ Decode and display JWT header and payload.
- 🔒 Validate standard claims (`exp`, `nbf`, `iat`) with security checks.
- 🚨 Detect dangerous algorithms like `alg: none`.
- 🌈 Color-coded CLI output for risk levels.
- 🧪 Built-in JWT generator with support for custom claims.
- 🌐 Flask API for easy integration.

---

## ⚙️ Usage Instructions

### 1. Clone the Repo
```bash
git clone https://github.com/Naveen898/jwt-analyzer.git
cd jwt-analyzer
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Flask API
```bash
cd api
python app.py
```
The API will start on [http://127.0.0.1:5001](http://127.0.0.1:5001).

### 4. Analyze a JWT via API
```bash
curl -X POST http://127.0.0.1:5001/analyze \
  -H "Content-Type: application/json" \
  -d '{"jwt": "<your-jwt-here>"}'
```

---

## 🖥️ CLI Usage

You can also use the CLI utility to analyze tokens:

```bash
python cli.py --jwt "<your-jwt-here>"
```

---

## 📝 API Response Example

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "1234567890",
    "name": "John Doe",
    "admin": true,
    "exp": 1749800255
  },
  "validation_issues": [
    "⚠️ HMAC algorithm used – ensure secure key handling"
  ],
  "signature_valid": true,
  "risk_level": "LOW",
  "iss": "https://issuer.example.com",
  "aud": "my-audience"
}
```

---

### 4. Token Generator 

```bash
python sample_tokens_generator.py
```
What it does:

- Prompts user for algorithm, standard & custom claims
- Supports both HMAC and RSA/ECDSA signing
- Outputs:
✅ Encoded JWT
✅ Decoded payload
✅ Timestamps (UNIX + human-readable format)

---

## 🛠️ Development

- Python 3.8+
- Flask
- [Other dependencies in `requirements.txt`]

---







