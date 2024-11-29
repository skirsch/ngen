import json
from flask import Flask, abort, request, jsonify, render_template, session
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
from dataclasses import asdict

# ============================================================================ #
#                                    GLOBALS                                   #
# ============================================================================ #
os.environ["WERKZEUG_DEBUG_PIN"] = "off"
# Global Challenge
global_challenge: bytes = b"dead beef hi hi hi test hi"

# ----------------------------- WENAUTHN GLOBALS ----------------------------- #
global_rp_id = "localhost"
global_rp_name = "ZeroID"


# Simulated database
users = {}


def random_alphanumeric_string(length: int):
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


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
#                        PASSKEY REGISTRATION GENERATION                       #
# ============================================================================ #
@app.get("/generate-registration-options")
def register_get():
    random_name = random_alphanumeric_string(6)
    session["user_name"] = random_name
    opts = options_to_json(
        generate_registration_options(
            rp_id=global_rp_id,
            rp_name=global_rp_name,
            user_name=random_name,
            challenge=global_challenge,
        )
    )
    print(opts)
    return opts


# ============================================================================ #
#                       PASSKEY REGISTRATION VERIFICATION                      #
# ============================================================================ #
@app.post("/verify-registration")
def register_post():
    if request.is_json:
        request_json = request.get_json()
        verification = verify_registration_response(
            credential=request_json,
            expected_challenge=global_challenge,
            expected_rp_id=global_rp_id,
            expected_origin="http://localhost:8080",
        )
        print(verification)
        verification_json = json.dumps(asdict(verification), default=str)
        print(verification_json)

        return verification_json
    abort(500)


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
