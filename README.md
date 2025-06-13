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

### 2. CLI Usage
```bash
python api/app.py

You'll be prompted to enter a JWT. The tool will decode and analyze it, printing results in a color-coded format.




