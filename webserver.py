from flask import Flask, request, jsonify, render_template, session
from fido2.server import Fido2Server
from fido2.webauthn import AttestationObject, AuthenticatorData
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_encode, websafe_decode
import base64
import os
import traceback
os.environ['WERKZEUG_DEBUG_PIN'] = 'off'

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
    with open('templates/index.html') as f:
        return f.read()

# Passkey Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        try:
            # Generate options for creating a new passkey
            user_id = os.urandom(8)  # Random user ID
            session['user_id'] = user_id.hex()
            user = PublicKeyCredentialUserEntity(
                id=user_id,
                name="test_user",
                display_name="Test User"
            )
            # Unpack the tuple returned by `register_begin`
            options, state = server.register_begin(user, user_verification="discouraged")
            session['challenge_state'] = state  # Store state in session directly

            # Access fields from `options.public_key` to create a JSON-compatible dictionary
            public_key_options = options.public_key
            options_dict = {
                "challenge": base64.b64encode(public_key_options.challenge).decode('utf-8'),
                "rp": {
                    "name": public_key_options.rp.name,
                    "id": public_key_options.rp.id
                },
                "user": {
                    "id": base64.b64encode(public_key_options.user.id).decode('utf-8'),
                    "name": public_key_options.user.name,
                    "displayName": public_key_options.user.display_name
                },
                "pubKeyCredParams": [
                    {
                        "type": param.type.value,
                        "alg": param.alg
                    } for param in public_key_options.pub_key_cred_params
                ],
                "timeout": public_key_options.timeout,
                "excludeCredentials": [
                    {
                        "id": base64.b64encode(cred.id).decode('utf-8'),
                        "type": cred.type
                    } for cred in (public_key_options.exclude_credentials or [])
                ],
                "authenticatorSelection": {
                    "authenticatorAttachment": public_key_options.authenticator_selection.authenticator_attachment if public_key_options.authenticator_selection.authenticator_attachment else None,
                    "residentKey": public_key_options.authenticator_selection.resident_key.value,
                    "userVerification": public_key_options.authenticator_selection.user_verification.value,
                    "requireResidentKey": public_key_options.authenticator_selection.require_resident_key
                },
                "attestation": public_key_options.attestation if public_key_options.attestation else None
            }

            # Send the `publicKey` options to the client
            return jsonify({"publicKey": options_dict})  # Only `options` is sent

        except Exception as e:
            traceback.print_exc()
            return jsonify({"status": "error", "message": str(e)}), 500

    if request.method == "POST":
        # Complete registration
        data = request.get_json()
        try:
            attestation_object = websafe_decode(data["attestationObject"])
            client_data = websafe_decode(data["clientDataJSON"])

            auth_data = server.register_complete(
                session["challenge_state"],
                client_data,
                AttestationObject(attestation_object),
            )

            # Store credential
            user_id = bytes.fromhex(session["user_id"])
            users[user_id] = {
                "credential_id": auth_data.credential_data.credential_id.hex(),
                "public_key": auth_data.credential_data.public_key
            }

            return jsonify({"status": "ok"})
        except Exception as e:
            traceback.print_exc()
            return jsonify({"status": "error", "message": str(e)}), 400

# Passkey Authentication
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        try:
            # Generate options for logging in
            credentials = [
                {
                    "id": base64.b64encode(bytes.fromhex(user["credential_id"])).decode('utf-8'),
                    "type": "public-key",
                }
                for user in users.values()
            ]
            options, state = server.authenticate_begin(credentials)
            session['challenge_state'] = state  # Store state in session directly

            # Access fields from `options` to create a JSON-compatible dictionary
            options_dict = {
                "challenge": base64.b64encode(options.challenge).decode('utf-8'),
                "timeout": options.timeout,
                "rpId": options.rp_id,
                "allowCredentials": [
                    {
                        "id": base64.b64encode(cred.id).decode('utf-8'),
                        "type": cred.type
                    } for cred in options.allow_credentials
                ],
                "userVerification": options.user_verification.value
            }

            return jsonify({"publicKey": options_dict})
        except Exception as e:
            traceback.print_exc()
            return jsonify({"status": "error", "message": str(e)}), 500

    if request.method == "POST":
        # Complete authentication
        data = request.get_json()
        try:
            credential_id = websafe_decode(data["credentialId"])
            client_data = websafe_decode(data["clientDataJSON"])
            auth_data = websafe_decode(data["authenticatorData"])
            signature = websafe_decode(data["signature"])

            # Find user by credential_id
            user = next(
                (user for user in users.values() if user["credential_id"] == credential_id.hex()), None
            )
            if not user:
                return jsonify({"status": "error", "message": "User not found"}), 400

            # Verify authentication
            server.authenticate_complete(
                session["challenge_state"],
                user["public_key"],
                AuthenticatorData(auth_data),
                client_data,
                signature,
            )
            return jsonify({"status": "ok"})
        except Exception as e:
            traceback.print_exc()
            return jsonify({"status": "error", "message": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True, port=8080)
