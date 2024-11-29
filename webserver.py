from flask import Flask, request, jsonify, render_template, session
from fido2.server import Fido2Server
from fido2.webauthn import AttestationObject, AuthenticatorData
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_encode, websafe_decode
import os
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
    with open("static/index.html") as f:
        return f.read()


# Passkey Registration
@app.get("/generate-registration-options")
def register_get():
    # Generate options for creating a new passkey
    user_id = random_alphanumeric_string(8)  # Random user ID
    # TO-DO
    return


@app.post("/verify-registration")
def register_post():
    # Complete registration
    return


# Passkey Authentication
@app.get("/login")
def login_get():
    # TO-DO
    return


@app.post("/login")
def login_post():
    # TO-DO
    return


if __name__ == "__main__":
    app.run(debug=True, port=8080)
