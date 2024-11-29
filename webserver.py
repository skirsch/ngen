import json
from flask import Flask, abort, request, jsonify, render_template, session
import os
import secrets
import string
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
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
    UserVerificationRequirement,
)
from dataclasses import asdict
import pickle
from threading import Lock

# ============================================================================ #
#                                    GLOBALS                                   #
# ============================================================================ #
os.environ["WERKZEUG_DEBUG_PIN"] = "off"
# Global Challenge
global_challenge: bytes = b"dead beef hi hi hi test hi"

# ----------------------------- WENAUTHN GLOBALS ----------------------------- #
global_rp_id = "localhost"
global_rp_name = "ZeroID"
global_expected_origin = "http://localhost:8080"

# ============================================================================ #
#                              SIMULATED DATABASE                              #
# ============================================================================ #
db_mutex = Lock()  # Prevent data-races. Use for "transactions".


def load_users():
    try:
        with db_mutex:
            with open("data.pkl", "rb") as f:
                return pickle.load(f)
    except FileNotFoundError:
        return {}  # Make an empty Dict if the file doesn't exist


users = load_users()


def save_users(users):
    with db_mutex:
        with open("data.pkl", "wb") as f:
            return pickle.dump(users, f)


# ============================================================================ #
#                                  MISCELLANY                                  #
# ============================================================================ #
def random_alphanumeric_string(length: int):
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def print_with_box(x):
    print(f"\n\n# ================================= #\n")
    print(x)
    print(f"\n# ================================= #\n\n")


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
    user_name = random_alphanumeric_string(6)
    session["user_name"] = user_name
    generated_registration_options = generate_registration_options(
        rp_id=global_rp_id,
        rp_name=global_rp_name,
        user_name=user_name,
        challenge=global_challenge,
    )

    opts = options_to_json(generated_registration_options)

    print_with_box(opts)

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

        if verification.user_verified == True:
            user_name = session["user_name"]
            print_with_box(user_name)
            users[user_name] = verification
            save_users(users)

            verification_json = json.dumps(asdict(verification), default=str)
            print_with_box(verification_json)
            return verification_json

    abort(500)


# ============================================================================ #
#                        PASSKEY AUTHENTICATION PHASE 1                        #
# ============================================================================ #
@app.get("/generate-authentication-options")
def login_get():
    user_name = session.get("user_name")
    if user_name is not None and user_name in users:
        print_with_box(users[user_name])
        verified_registration = users[user_name]
        auth_options = generate_authentication_options(
            rp_id=global_rp_id,
            challenge=global_challenge,
            user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=verified_registration.credential_id)
            ],
        )
        opts = options_to_json()

        print_with_box(opts)

        return opts

    abort(500)


# ============================================================================ #
#                        PASSKEY AUTHENTICATION PHASE 2                        #
# ============================================================================ #
@app.post("/verify-authentication")
def login_post():
    if request.is_json:
        request_json = request.get_json()
        verification = verify_authentication_response(
            credential=request_json,
            expected_challenge=global_challenge,
            expected_rp_id=global_rp_id,
            expected_origin="http://localhost:8080",
        )
        verification_json = json.dumps(asdict(verification), default=str)
        print_with_box(verification_json)

        return verification_json

    abort(500)


# ============================================================================ #
#                                  ENTRY POINT                                 #
# ============================================================================ #
if __name__ == "__main__":
    app.run(debug=True, port=8080)
