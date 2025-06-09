# # Handling modules
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# api/app.py
from flask import Flask, request, jsonify
from analyzer.decoder import JWTDecoder
from analyzer.validator import JWTValidator
from analyzer.security import JWTSecurity
from analyzer.utils import log_analysis

app = Flask(__name__)

"""@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    token = data.get("jwt")
    secret = data.get("secret", None)

    if not token:
        return jsonify({"error": "JWT token missing"}), 400

    try:
        decoded = JWTDecoder(token)
        validator = JWTValidator(decoded)
        validator.validate()
        validation_issues = validator.issues

        signature_valid = None
        if secret:
            signature_valid = JWTSecurity.verify_signature(token, secret)

        result = {
            "header": decoded["header"],
            "payload": decoded["payload"],
            "validation_issues": validation_issues,
            "signature_valid": signature_valid
        }

        log_analysis(str(result))
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
"""

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    token = data.get("jwt")
    secret = data.get("secret", None)

    if not token:
        return jsonify({"error": "JWT token missing"}), 400

    try:
        decoder = JWTDecoder(token)
        decoded = decoder.decode()  # <-- decode the token!
        validator = JWTValidator(decoded)
        validator.validate()
        validation_issues = validator.issues

        signature_valid = None
        if secret:
            security = JWTSecurity(token, decoded.get("header", {}), decoded.get("payload", {}))
            signature_valid = security.verify_signature(secret)

        result = {
            "header": decoded["header"],
            "payload": decoded["payload"],
            "validation_issues": validation_issues,
            "signature_valid": signature_valid
        }

        log_analysis(str(result))
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
def log_analysis(message):
    with open("analysis.log", "a") as f:
        f.write(message + "\n")

if __name__ == "__main__":
    print("🚀 Flask app is starting...")
    app.run(debug=True, port=5001)  # Change port here

    