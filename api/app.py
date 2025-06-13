# # Handling modules
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# api/app.py
from flask import Flask, request, jsonify
from analyzer.decoder import JWTDecoder
from analyzer.validator import JWTValidator
from analyzer.security import JWTSecurity
from utils.logger import setup_logger, log_token_analysis
import re

app = Flask(__name__)
setup_logger()

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

        # Log the analysis
        def strip_formatting(text):
            return re.sub(r'\[/?[a-z0-9]+\]', '', text)

        cleaned_issues = [strip_formatting(issue) for issue in validation_issues]

        #Original result structure
        """result = {
            "header": decoded["header"],
            "payload": decoded["payload"],
            "validation_issues": cleaned_issues,
            "signature_valid": signature_valid
        }"""
        # Updated result structure-START
        # Determine risk level based on issues
        if any("❌" in issue for issue in validation_issues):
            risk_level = "HIGH"
        elif validation_issues:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Extract optional fields if available
        payload = decoded.get("payload", {})
        issuer = payload.get("iss")
        audience = payload.get("aud")

        result = {
            "header": decoded["header"],
            "payload": payload,
            "validation_issues": cleaned_issues,
            "signature_valid": signature_valid,
            "risk_level": risk_level
        }

        # Only include optional fields if they exist
        if issuer:
            result["iss"] = issuer
        if audience:
            result["aud"] = audience
        # Updated result structure-END

        log_token_analysis(
            token_snippet=token[:20] + "...",
            risk_level="HIGH" if validation_issues else "LOW",
            issues_found="; ".join(cleaned_issues),
            source="API"
        )
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("🚀 Flask app is starting...")
    app.run(debug=True, port=5001)  # Change port here

    