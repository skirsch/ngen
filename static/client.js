const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser
window.registerPasskey = async function() {
  // Fetch Options from Server
  const resp = await fetch('/generate-registration-options')
  const optionsJSON = await resp.json()

  let attResp
  try {
    // Pass the options to the authenticator and wait for a response
    attResp = await startRegistration({ optionsJSON })
  } catch (error) {
    // Some basic error handling
    if (error.name === 'InvalidStateError') {
      console.error('Error: Authenticator was probably already registered by user')
    }
    throw error
  }

  console.log(attResp)

  // POST the response to the endpoint that calls
  // @simplewebauthn/server -> verifyRegistrationResponse()
  const verificationResp = await fetch('/verify-registration', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(attResp),
  })

  // Wait for the results of verification
  const verificationJSON = await verificationResp.json()

  alert('Passkey registration successful!')
}

window.loginPasskey = async function() {
  // GET authentication options from the endpoint that calls
  // @simplewebauthn/server -> generateAuthenticationOptions()
  const resp = await fetch('/generate-authentication-options')
  const optionsJSON = await resp.json()

  let asseResp
  // Pass the options to the authenticator and wait for a response
  asseResp = await startAuthentication({ optionsJSON })
  console.log(asseResp)

  // POST the response to the endpoint that calls
  // @simplewebauthn/server -> verifyAuthenticationResponse()
  const verificationResp = await fetch('/verify-authentication', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(asseResp),
  })

  // Wait for the results of verification
  const verificationJSON = await verificationResp.json()
  alert('Passkey registration successful!')
}
