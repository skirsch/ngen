from flask import Flask, request, jsonify, render_template, session
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_encode, websafe_decode
import os

# Flask app setup
app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# WebAuthn setup
rp = PublicKeyCredentialRpEntity(id="localhost", name="My WebAuthn Server")
server = Fido2Server(rp)

# Simulated database
users = {}

# Home page
@app.route("/")
def home():
    return """
    <h1>Welcome to the WebAuthn Demo</h1>
    <button onclick="window.location.href='/register'">Create a Passkey</button>
    <button onclick="window.location.href='/login'">Login via Passkey</button>
    """

# Passkey Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        # Generate options for creating a new passkey
        user_id = os.urandom(8)  # Random user ID
        session['user_id'] = user_id.hex()
        user = PublicKeyCredentialUserEntity(
            id=user_id,
            name="test_user",
            display_name="Test User"
        )
        options = server.register_begin(user, user_verification="discouraged")
        session['challenge'] = websafe_encode(options["publicKey"]["challenge"])
        return jsonify(options)

    if request.method == "POST":
        # Complete registration
        data = request.get_json()
        attestation_object = websafe_decode(data["attestationObject"])
        client_data = websafe_decode(data["clientDataJSON"])

        auth_data = server.register_complete(
            session["challenge"],
            client_data,
            AttestationObject(attestation_object),
        )

        # Store credential
        user_id = bytes.fromhex(session["user_id"])
        users[user_id] = {
            "credential_id": auth_data.credential_data.credential_id,
            "public_key": auth_data.credential_data.public_key,
        }

        return jsonify({"status": "ok"})

# Passkey Authentication
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Generate options for logging in
        credentials = [
            {
                "id": websafe_encode(user["credential_id"]),
                "type": "public-key",
            }
            for user in users.values()
        ]
        options = server.authenticate_begin(credentials)
        session['challenge'] = websafe_encode(options["publicKey"]["challenge"])
        return jsonify(options)

    if request.method == "POST":
        # Complete authentication
        data = request.get_json()
        credential_id = websafe_decode(data["credentialId"])
        client_data = websafe_decode(data["clientDataJSON"])
        auth_data = websafe_decode(data["authenticatorData"])
        signature = websafe_decode(data["signature"])

        # Find user by credential_id
        user = next(
            (user for user in users.values() if user["credential_id"] == credential_id), None
        )
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 400

        # Verify authentication
        server.authenticate_complete(
            session["challenge"],
            user["public_key"],
            AuthenticatorData(auth_data),
            client_data,
            signature,
        )
        return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=True)
