"""Sign-in: Google / Microsoft (OpenID Connect, authorization code + PKCE) and passkeys (WebAuthn with PRF).

Identity comes from Google or Microsoft; the passkey proves the person is present and, through the PRF
extension, yields the secret that opens their key to the vault. A user is bound to the provider's stable
subject on first sign-in (through an invite), so a changed or spoofed e-mail claim can't take over an account.
"""
import base64
import hashlib
import json
import secrets
import time
import urllib.parse
import urllib.request

import jwt
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

PROVIDERS = {
    "google": {
        "label": "Google",
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "jwks": "https://www.googleapis.com/oauth2/v3/certs",
        "issuers": ("https://accounts.google.com", "accounts.google.com"),
        "scope": "openid email profile",
    },
    "microsoft": {
        "label": "Microsoft",
        "authorize": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "jwks": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        "issuers": None,            # per tenant: https://login.microsoftonline.com/{tid}/v2.0
        "scope": "openid email profile",
    },
}
_jwks = {}


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# -- OpenID Connect -------------------------------------------------------------------------
def authorize_url(provider, client_id, redirect_uri, login_hint=None):
    """Returns (url, state record to keep server-side)."""
    p = PROVIDERS[provider]
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = b64u(hashlib.sha256(verifier.encode()).digest())
    q = {"client_id": client_id, "response_type": "code", "redirect_uri": redirect_uri, "scope": p["scope"],
         "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256",
         "prompt": "select_account"}
    if login_hint:
        q["login_hint"] = login_hint
    return f'{p["authorize"]}?{urllib.parse.urlencode(q)}', {"state": state, "nonce": nonce, "verifier": verifier,
                                                             "provider": provider, "created": time.time()}


def exchange_code(provider, client_id, client_secret, redirect_uri, code, pending):
    """Swap the code for tokens and verify the ID token. Returns the verified identity."""
    p = PROVIDERS[provider]
    body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                                   "client_id": client_id, "client_secret": client_secret,
                                   "code_verifier": pending["verifier"]}).encode()
    req = urllib.request.Request(p["token"], data=body, headers={"Content-Type": "application/x-www-form-urlencoded",
                                                                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            tokens = json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = json.loads(e.read() or b"{}").get("error_description", "")
        raise ValueError(f"{p['label']} refused the sign-in: {detail[:200]}")
    if provider not in _jwks:
        _jwks[provider] = jwt.PyJWKClient(p["jwks"], cache_keys=True, lifespan=3600)
    key = _jwks[provider].get_signing_key_from_jwt(tokens["id_token"]).key
    claims = jwt.decode(tokens["id_token"], key, algorithms=["RS256"], audience=client_id,
                        options={"require": ["exp", "iat", "sub", "iss", "aud"]}, leeway=60)
    if claims.get("nonce") != pending["nonce"]:
        raise ValueError("Sign-in reply didn't match this request")
    if provider == "google":
        if claims["iss"] not in p["issuers"]:
            raise ValueError("Unexpected issuer")
        if not claims.get("email_verified"):
            raise ValueError("Your Google e-mail address isn't verified")
        email = claims["email"]
        subject = claims["sub"]
    else:
        tid = claims.get("tid", "")
        if claims["iss"] != f"https://login.microsoftonline.com/{tid}/v2.0":
            raise ValueError("Unexpected issuer")
        email = claims.get("email") or claims.get("preferred_username") or ""
        subject = f'{tid}:{claims.get("oid") or claims["sub"]}'
    if "@" not in email:
        raise ValueError("Your account didn't share an e-mail address")
    return {"provider": provider, "subject": subject, "email": email.lower(), "name": claims.get("name") or email}


# -- passkeys -------------------------------------------------------------------------------
def registration_options(rp_id, user, existing):
    opts = generate_registration_options(
        rp_id=rp_id, rp_name="AI IT Guardian", user_id=user["id"].encode(), user_name=user["email"],
        user_display_name=user["name"],
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.REQUIRED,
                                                               user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=b64u_dec(c["id"])) for c in existing])
    data = json.loads(options_to_json(opts))
    data["extensions"] = {"prf": {}, "credProps": True}
    return data, opts.challenge


def verify_registration(credential, challenge, rp_id, origins):
    v = verify_registration_response(credential=credential, expected_challenge=challenge, expected_rp_id=rp_id,
                                     expected_origin=origins, require_user_verification=True)
    return b64u(v.credential_id), v.credential_public_key, v.sign_count


def authentication_options(rp_id, credentials, prf_salt):
    """Empty credentials = let the person pick any passkey for this site (sign-in without Google/Microsoft).
    One PRF input for every credential: each passkey still produces its own, unrelated secret from it."""
    opts = generate_authentication_options(
        rp_id=rp_id, allow_credentials=[PublicKeyCredentialDescriptor(id=b64u_dec(c["id"])) for c in credentials],
        user_verification=UserVerificationRequirement.REQUIRED)
    data = json.loads(options_to_json(opts))
    data["extensions"] = {"prf": {"eval": {"first": b64u(prf_salt)}}}
    return data, opts.challenge


def verify_authentication(credential, challenge, rp_id, origins, stored):
    v = verify_authentication_response(credential=credential, expected_challenge=challenge, expected_rp_id=rp_id,
                                       expected_origin=origins, credential_public_key=stored["public_key"],
                                       credential_current_sign_count=stored["sign_count"], require_user_verification=True)
    return v.new_sign_count
