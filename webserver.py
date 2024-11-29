from flask import Flask, request, jsonify, render_template, session
from fido2.server import Fido2Server
from fido2.webauthn import AttestationObject, AuthenticatorData
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_encode, websafe_decode
import os
import secrets
import string
import fido2.features
fido2.features.webauthn_json_mapping.enabled = True

os.environ["WERKZEUG_DEBUG_PIN"] = "off"


def random_alphanumeric_string(length: int):
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


# Flask app setup
app = Flask(__name__)
app.secret_key = random_alphanumeric_string(24)  # For session management


# WebAuthn setup
rp = PublicKeyCredentialRpEntity(id="localhost", name="My WebAuthn Server")
server = Fido2Server(rp)

# Global Challenge
global_challenge: bytes = b"dead beef"

# Simulated database
users = {}


# Home page
@app.route("/")
def home():
    with open("static/index.html") as f:
        return f.read()


# Passkey Registration
@app.get("/generate-registration-options")
def register_get():
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=bytes(random_alphanumeric_string(8), 'utf-8'),  # Convert string to bytes
            name="user",
            display_name="User",
        ),
        users.get('credentials', []),  # Use existing credentials if any
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )
    
    session["state"] = state
    return jsonify(dict(options))


@app.post("/verify-registration")
def register_post():
    try:
        response = request.json
        auth_data = server.register_complete(session["state"], response)
        
        # Store the credential data
        if 'credentials' not in users:
            users['credentials'] = []
        users['credentials'].append(auth_data.credential_data)
        
        return jsonify({"status": "OK"})
    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)}), 400


# Passkey Authentication
@app.get("/generate-authentication-options")
def login_get():
    if 'credentials' not in users or not users['credentials']:
        return jsonify({"error": "No credentials registered"}), 404
        
    options, state = server.authenticate_begin(users['credentials'])
    session["state"] = state
    return jsonify(dict(options))


@app.post("/verify-authentication")
def login_post():
    if 'credentials' not in users or not users['credentials']:
        return jsonify({"error": "No credentials registered"}), 404
        
    try:
        response = request.json
        server.authenticate_complete(
            session.pop("state"),
            users['credentials'],
            response,
        )
        return jsonify({"status": "OK"})
    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True, port=8080)
