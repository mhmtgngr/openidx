#!/usr/bin/env python3
"""Register what the conformance plans need in a running OpenIDX, and render
the plan configurations the suite is given.

For each template in plans/ this creates, through OpenIDX's own admin APIs:

  * one end user, with a password generated for this run, through
    POST /api/v1/identity/users and .../set-password on identity-service;
  * the static OAuth clients the plan needs, through POST /api/v1/oauth/clients
    on oauth-service, registered with the redirect, post-logout and
    back-channel logout URIs the suite expects for the template's alias;

and writes the template with those values filled in to --out.

Every plan gets its own user. The logout plans end every session of the user
they sign in as, and the back-channel plan counts the logout tokens it
receives, so sharing one user between plans would let one plan's logout reach
another plan's sessions.

The admin token comes from the seeded first-run administrator signing in to
the admin-console client with PKCE, as scripts/smoke-test.sh does. That
credential (admin / Admin@123) is public by design and only works on a
development install; production refuses to start while it is set.

Nothing secret is printed. Under GitHub Actions every generated secret is
registered with ::add-mask:: before anything else is written, and
--secrets-file receives them (one per line) so the results can be scrubbed
before they are uploaded (redact.py).

Standard library only.
"""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent

# What each plan template needs registered. The alias comes from the template
# itself; it decides every URI the suite will use for that plan.
REGISTRATIONS = {
    "openidx-basic.json": {
        "user": "basic",
        # Basic OP's refresh-token module uses a second client, to check that a
        # refresh token issued to one client is refused for the other. The
        # template's client_secret_post block (the suite allows a separate
        # client there, for servers that tie a client to one authentication
        # method) reuses the first client: OpenIDX accepts both methods from
        # every confidential client.
        "clients": ["CLIENT", "CLIENT2"],
        "post_logout": False,
        "backchannel": False,
    },
    "openidx-rp-logout.json": {
        "user": "rp-logout",
        "clients": ["CLIENT"],
        "post_logout": True,
        "backchannel": False,
    },
    "openidx-backchannel-logout.json": {
        "user": "backchannel",
        "clients": ["CLIENT"],
        "post_logout": True,
        "backchannel": True,
    },
}

ADMIN_CLIENT_ID = "admin-console"
ADMIN_REDIRECT_URI = "http://localhost:3000/callback"


class SetupError(Exception):
    pass


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def request(method, url, *, json_body=None, form=None, token=None, expect=(200,)):
    """One HTTP call. Returns (status, headers, parsed JSON or None).

    Bodies are never echoed on failure: the requests carry passwords and the
    responses carry client secrets. The status and the error code are enough
    to act on.
    """
    headers = {"Accept": "application/json"}
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = _opener.open(req, timeout=30)
        status, resp_headers, body = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as err:
        status, resp_headers, body = err.code, err.headers, err.read()
    parsed = None
    if body:
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
    if status not in expect:
        code = parsed.get("error") if isinstance(parsed, dict) else None
        raise SetupError("%s %s answered %d%s" % (
            method, urllib.parse.urlsplit(url).path, status, " (%s)" % code if code else ""))
    return status, resp_headers, parsed


class Masker:
    """Registers secrets with the runner, and remembers them for redact.py."""

    def __init__(self):
        self.values = []
        self.actions = os.environ.get("GITHUB_ACTIONS") == "true"

    def add(self, value):
        if not value:
            return
        self.values.append(value)
        if self.actions:
            print("::add-mask::" + value, flush=True)

    def add_basic_auth(self, client_id, secret):
        # The suite logs its token requests, Authorization header included:
        # the client's secret appears there only in this encoded form.
        pair = "%s:%s" % (urllib.parse.quote(client_id, safe=""), urllib.parse.quote(secret, safe=""))
        self.add(base64.b64encode(pair.encode()).decode("ascii"))


def admin_token(oauth_url, username, password, masker):
    verifier = b64url(secrets.token_bytes(48))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    query = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": ADMIN_CLIENT_ID,
        "redirect_uri": ADMIN_REDIRECT_URI,
        "scope": "openid profile email",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    _, headers, _ = request("GET", oauth_url + "/oauth/authorize?" + query, expect=(302,))
    location = headers.get("Location", "")
    login_session = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get("login_session", [""])[0]
    if not login_session:
        raise SetupError("/oauth/authorize did not redirect to the login page with a login_session")

    _, _, login = request("POST", oauth_url + "/oauth/login", json_body={
        "username": username, "password": password, "login_session": login_session})
    redirect = (login or {}).get("redirect_url", "")
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(redirect).query).get("code", [""])[0]
    if not code:
        raise SetupError("the administrator's login did not end in an authorization code "
                         "(an MFA or consent step is not handled here)")

    _, _, tokens = request("POST", oauth_url + "/oauth/token", form={
        "grant_type": "authorization_code",
        "code": code,
        "client_id": ADMIN_CLIENT_ID,
        "redirect_uri": ADMIN_REDIRECT_URI,
        "code_verifier": verifier,
    })
    token = (tokens or {}).get("access_token", "")
    if not token:
        raise SetupError("/oauth/token returned no access_token for the administrator")
    masker.add(token)
    return token


def new_password():
    # Meets the password policy (upper, lower, digit, symbol) whatever the
    # random part draws, and stays inside characters that need no escaping
    # in JSON or in the browser automation that types it.
    return "Cf7!" + secrets.token_urlsafe(18)


def create_user(identity_url, token, label, run_id, masker):
    username = "conformance-%s-%s" % (label, run_id)
    _, _, user = request("POST", identity_url + "/api/v1/identity/users", token=token, json_body={
        "userName": username,
        "name": {"givenName": label.replace("-", " ").title(), "familyName": "Conformance"},
        "emails": [{"value": username + "@example.com", "primary": True}],
        "enabled": True,
        "emailVerified": True,
    }, expect=(200, 201))
    user_id = (user or {}).get("id", "")
    if not user_id:
        raise SetupError("creating user %s returned no id" % username)
    password = new_password()
    masker.add(password)
    request("POST", "%s/api/v1/identity/users/%s/set-password" % (identity_url, user_id),
            token=token, json_body={"password": password})
    return username, password


def create_client(oauth_url, token, name, uris, masker):
    body = {
        "name": name,
        "description": "OpenID conformance run: " + name,
        "type": "confidential",
        "redirect_uris": [uris["redirect"]],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scopes": ["openid", "profile", "email", "offline_access"],
        "pkce_required": False,
        "allow_refresh_token": True,
        "access_token_lifetime": 3600,
        "refresh_token_lifetime": 86400,
    }
    if uris.get("post_logout"):
        body["post_logout_redirect_uris"] = [uris["post_logout"]]
    if uris.get("backchannel"):
        body["back_channel_logout_uri"] = uris["backchannel"]
    _, _, client = request("POST", oauth_url + "/api/v1/oauth/clients", token=token,
                           json_body=body, expect=(200, 201))
    client_id = (client or {}).get("client_id", "")
    secret = (client or {}).get("client_secret", "")
    if not client_id or not secret:
        raise SetupError("registering client %r returned no client_id or client_secret" % name)
    masker.add(secret)
    masker.add_basic_auth(client_id, secret)
    return client_id, secret


def render(template_text, values):
    out = template_text
    for key, value in values.items():
        # Values land inside JSON strings: escape them as JSON would.
        out = out.replace("@@%s@@" % key, json.dumps(value)[1:-1])
    if "@@" in out:
        left = sorted(set(part.split("@@")[0] for part in out.split("@@")[1::2]))
        raise SetupError("unfilled placeholders: %s" % ", ".join(left))
    json.loads(out)  # a template that does not render to JSON is a defect here, not in the suite
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", required=True, help="directory for the rendered plan configurations")
    parser.add_argument("--secrets-file", help="write every generated secret here, one per line, for redact.py")
    parser.add_argument("--oauth-url", default=os.environ.get("OPENIDX_OAUTH_URL", "http://localhost:8006"))
    parser.add_argument("--identity-url", default=os.environ.get("OPENIDX_IDENTITY_URL", "http://localhost:8001"))
    parser.add_argument("--issuer", default=os.environ.get("OAUTH_ISSUER", "https://op.openidx.test"))
    parser.add_argument("--suite-url", default="https://localhost.emobix.co.uk:8443",
                        help="the suite's BASE_URL, which every URI it hands out starts with")
    parser.add_argument("--plans-dir", default=str(HERE / "plans"))
    args = parser.parse_args()

    masker = Masker()
    run_id = secrets.token_hex(3)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    token = admin_token(args.oauth_url.rstrip("/"),
                        os.environ.get("OPENIDX_ADMIN_USERNAME", "admin"),
                        os.environ.get("OPENIDX_ADMIN_PASSWORD", "Admin@123"),
                        masker)

    suite = args.suite_url.rstrip("/")
    for template_name, reg in REGISTRATIONS.items():
        template_text = (pathlib.Path(args.plans_dir) / template_name).read_text()
        alias = json.loads(template_text).get("alias", "")
        if not alias:
            raise SetupError("%s has no alias; static clients need one" % template_name)
        base = "%s/test/a/%s" % (suite, alias)
        uris = {"redirect": base + "/callback"}
        if reg["post_logout"]:
            uris["post_logout"] = base + "/post_logout_redirect"
        if reg["backchannel"]:
            uris["backchannel"] = base + "/backchannel_logout"

        username, password = create_user(args.identity_url.rstrip("/"), token, reg["user"], run_id, masker)
        values = {"OP_ISSUER": args.issuer.rstrip("/"), "SUITE_URL": suite,
                  "USERNAME": username, "PASSWORD": password}
        client_ids = []
        for slot in reg["clients"]:
            name = "conformance %s %s" % (alias, slot.lower())
            client_id, secret = create_client(args.oauth_url.rstrip("/"), token, name, uris, masker)
            values[slot + "_ID"] = client_id
            values[slot + "_SECRET"] = secret
            client_ids.append(client_id)

        target = out / template_name
        target.write_text(render(template_text, values))
        target.chmod(0o600)
        print("%s: user %s, client(s) %s, alias %s" % (template_name, username, ", ".join(client_ids), alias))

    if args.secrets_file:
        path = pathlib.Path(args.secrets_file)
        path.write_text("".join(v + "\n" for v in masker.values))
        path.chmod(0o600)


if __name__ == "__main__":
    try:
        main()
    except SetupError as err:
        print("setup_openidx: " + str(err), file=sys.stderr)
        sys.exit(1)
