from flask import Flask, request, jsonify, render_template, session
import os
import secrets
import string
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
)

# ============================================================================ #
#                                    GLOBALS                                   #
# ============================================================================ #
os.environ["WERKZEUG_DEBUG_PIN"] = "off"
# Global Challenge
global_challenge: bytes = b"dead beef"

# Simulated database
users = {}


def random_alphanumeric_string(length: int):
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


# ----------------------------- AUTH BOILERPLATE ----------------------------- #
simple_registration_options = generate_registration_options(
    rp_id="example.com",
    rp_name="Example Co",
    user_name="bob",
)

print("\n[Registration Options - Simple]")
print(options_to_json(simple_registration_options))


# ============================================================================ #
#                                  FLASK SETUP                                 #
# ============================================================================ #
app = Flask(__name__)
app.secret_key = random_alphanumeric_string(24)  # For session management CHANGE IN PROD


# --------------------------------- HOME PAGE -------------------------------- #
@app.route("/")
def home():
    # TODO: Change to use Flask/Jinja2 templating
    with open("static/index.html") as f:
        return f.read()


# ============================================================================ #
#                         PASSKEY REGISTRATION PHASE 1                         #
# ============================================================================ #
@app.get("/generate-registration-options")
def register_get():
    # FIXME: IMPLEMENT
    return


# ============================================================================ #
#                         PASSKEY REGISTRATION PHASE 2                         #
# ============================================================================ #
@app.post("/verify-registration")
def register_post():
    # FIXME: IMPLEMENT
    return


# ============================================================================ #
#                        PASSKEY AUTHENTICATION PHASE 1                        #
# ============================================================================ #
@app.get("/generate-authentication-options")
def login_get():
    # FIXME: IMPLEMENT
    return


# ============================================================================ #
#                        PASSKEY AUTHENTICATION PHASE 2                        #
# ============================================================================ #
@app.post("/verify-authentication")
def login_post():
    # FIXME: IMPLEMENT
    return


# ============================================================================ #
#                                  ENTRY POINT                                 #
# ============================================================================ #
if __name__ == "__main__":
    app.run(debug=True, port=8080)
