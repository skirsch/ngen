from flask import Flask, request, jsonify, render_template, session
from fido2.server import Fido2Server
from fido2.webauthn import AttestationObject, AuthenticatorData
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_encode, websafe_decode
import base64
import os
import traceback
import secrets
import string


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
    with open("templates/index.html") as f:
        return f.read()


# Passkey Registration
@app.get("/register")
def register_get():
    # Generate options for creating a new passkey
    user_id = random_alphanumeric_string(8)  # Random user ID
    user = PublicKeyCredentialUserEntity(
        id=user_id, name="test_user", display_name="Test User"
    )
    # Unpack the tuple returned by `register_begin` to CredentialCreationOptions, State
    # These will need to be fed in to `register_complete`
    options, state = server.register_begin(user, user_verification="discouraged")

    # Access fields from `options.public_key` to create a JSON-compatible dictionary
    public_key_options = options.public_key

    # Send the `publicKey` options to the client
    return {"publicKey": public_key_options, "state": state}


@app.post("/register")
def register_post():
    # Complete registration
    data = request.get_json()
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
        "public_key": auth_data.credential_data.public_key,
    }

    return {"status": "ok"}


# Passkey Authentication
@app.get("/login")
def login_get():
    # Generate options for logging in
    credentials = [
        {
            "id": base64.b64encode(bytes.fromhex(user["credential_id"])).decode(
                "utf-8"
            ),
            "type": "public-key",
        }
        for user in users.values()
    ]
    options, state = server.authenticate_begin(credentials)
    session["challenge_state"] = state  # Store state in session directly

    # Access fields from `options` to create a JSON-compatible dictionary
    options_dict = {
        "challenge": base64.b64encode(options.challenge).decode("utf-8"),
        "timeout": options.timeout,
        "rpId": options.rp_id,
        "allowCredentials": [
            {"id": base64.b64encode(cred.id).decode("utf-8"), "type": cred.type}
            for cred in options.allow_credentials
        ],
        "userVerification": options.user_verification.value,
    }

    return jsonify({"publicKey": options_dict})


@app.post("/login")
def login_post():
    # Complete authentication



if __name__ == "__main__":
    app.run(debug=True, port=8080)
