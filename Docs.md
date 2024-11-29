# Control Flow

## Creation:
#### Client
1. "Create a Passkey" Button is Clicked
2. `registerPasskey()` called
3. `fetch` `/register` with `GET` request
#### Server
1. `user_id` = random 8 character ID
2. `session['user_id']` stores `user_id.hex()` in the [session](https://flask.palletsprojects.com/en/stable/quickstart/#sessions)
3. `user` = `PublicKeyCredentialUserEntity(id, name, display_name)`
4. `server.register_begin(user, user_verification='discouraged')` is called, Returning a `CredentialCreationOptions` registration object and the internal state dictionary that needs to be passed as is to the corresponding `register_complete` call.

    a. *Note: You can get the `PublicKeyCredentialCreationOptions` out of the `CredentialCreationOptions` object...*

    b. *See: [PublicKeyCredentialCreationOptions on MDN](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions)*





What the fuck is this
```
base64.b64encode(options.challenge).decode("utf-8")
```