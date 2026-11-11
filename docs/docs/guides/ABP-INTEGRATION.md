# Signing in to an ABP application with OpenIDX

This guide connects an [ABP Framework](https://abp.io) application (ASP.NET
Core, with or without its own OpenIddict server) to OpenIDX over OpenID
Connect. OpenIDX authenticates the person, applies MFA policies, application
assignment and device trust, and the ABP application keeps its own users,
roles and permissions.

Use OIDC, not SAML: SAML sign-on to applications is not supported
([SAML guide](SAML.md)).

## 1. Register the application in OpenIDX

In the admin console, **Applications → Register application**:

| Field | Value |
| --- | --- |
| Type | Web (confidential) for an MVC / Blazor Server app; SPA (public) for Angular or Blazor WASM |
| Redirect URIs | `https://<app-host>/signin-oidc` (one per environment, see section 6) |
| Post-logout redirect URIs | `https://<app-host>/signout-callback-oidc` |
| Back-channel logout URI | `https://<app-host>/signout-oidc-backchannel` (optional, section 5) |
| PKCE | required |

Keep the client id and, for a confidential client, the secret.

Then, on the application's menu:

- **Manage access**: assign the users or groups who may sign in, and turn on
  *require assignment* if nobody else should.
- **Access conditions**: tick *Require a fresh second factor* for an
  application that should always ask for one (this makes every sign-in ask
  for `urn:openidx:mfa:fresh`, whatever the application sends). Device trust,
  a risk ceiling and allowed countries are set here too.

## 2. Configure the OIDC handler

ABP's web host adds an external login through ASP.NET Core's
`AddOpenIdConnect`. In the module's `ConfigureServices`
(`<Project>WebModule` or `<Project>HttpApiHostModule`):

```csharp
context.Services.AddAuthentication()
    .AddOpenIdConnect("OpenIDX", "OpenIDX", options =>
    {
        options.Authority = "https://openidx.tdv.org";
        options.ClientId = configuration["OpenIDX:ClientId"];
        options.ClientSecret = configuration["OpenIDX:ClientSecret"]; // confidential clients only
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.MapInboundClaims = false;

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");

        options.TokenValidationParameters.NameClaimType = "preferred_username";
        options.TokenValidationParameters.RoleClaimType = "roles";

        options.Events.OnRedirectToIdentityProvider = ctx =>
        {
            // Ask for a second factor in this session. Use
            // urn:openidx:mfa:fresh to ask for one within the step-up window,
            // or urn:openidx:phishing-resistant for a passkey.
            ctx.ProtocolMessage.AcrValues = "urn:openidx:mfa";
            return Task.CompletedTask;
        };
    });
```

Notes:

- The authority is the issuer. Discovery is at
  `https://openidx.tdv.org/.well-known/openid-configuration`, and the handler
  reads the endpoints and signing keys from it.
- `roles` and `groups` are always in the ID token, whatever the scope (they
  are authorization facts, not profile claims). Ask for the `roles` or
  `groups` scope only if it is registered on the client: a scope the client
  does not have is refused with `invalid_scope`.
- `email` and `email_verified` need the `email` scope; `name`,
  `given_name`, `family_name` need `profile`.

### What the ID token says about the sign-in

| Claim | Meaning |
| --- | --- |
| `acr` | the strongest class the session satisfies: `urn:openidx:pwd`, `urn:openidx:mfa`, `urn:openidx:mfa:fresh` or `urn:openidx:phishing-resistant` |
| `amr` | the methods used, for example `["pwd","mfa"]` or `["pwd","hwk","mfa"]` |
| `auth_time` | when the person signed in (with single sign-on, earlier than `iat`) |
| `sid` | the OpenIDX session, the key back-channel logout uses |

OpenIDX does not issue a code until the session satisfies `acr_values`: the
person is asked for the second factor on the OpenIDX login page first. Check
`acr` anyway for a page that needs more than the rest of the application:

```csharp
var acr = User.FindFirst("acr")?.Value;
if (acr != "urn:openidx:mfa:fresh" && acr != "urn:openidx:phishing-resistant")
{
    return Challenge(new AuthenticationProperties
    {
        RedirectUri = Request.Path,
        Items = { ["acr_values"] = "urn:openidx:mfa:fresh" }
    }, "OpenIDX");
}
```

and pass the item on in `OnRedirectToIdentityProvider`
(`ctx.Properties.Items.TryGetValue("acr_values", out var acr)`).

To make the person type their password again, set
`ctx.ProtocolMessage.Prompt = "login"`. With `prompt=none` OpenIDX answers
`login_required` or `interaction_required` at the redirect URI instead of
showing a page.

## 3. Link OpenIDX identities to ABP users

ABP's account module handles an external login in
`LoginModel.OnGetExternalLoginCallbackAsync`. Link by the OpenIDX subject
first, and by e-mail only when OpenIDX says the address is verified:

```csharp
var info = await SignInManager.GetExternalLoginInfoAsync();
var user = await UserManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
if (user == null)
{
    var email = info.Principal.FindFirstValue("email");
    var verified = string.Equals(info.Principal.FindFirstValue("email_verified"), "true",
        StringComparison.OrdinalIgnoreCase);
    if (!string.IsNullOrEmpty(email) && verified)
    {
        user = await UserManager.FindByEmailAsync(email);
        if (user != null)
        {
            (await UserManager.AddLoginAsync(user, info)).CheckErrors();
        }
    }
}
```

- `ProviderKey` is the `sub` claim. It is stable for a user and a client.
  With pairwise subjects turned on (`OIDC_PAIRWISE_SUBJECTS`) it differs per
  client, so link each ABP application on its own.
- Never link on an unverified address. Matching an account by an address the
  person has not proved is an account-takeover path, which is why OpenIDX
  reads `email_verified` from the user record rather than asserting it.
- Accounts that live only in the application (local ABP users) keep working.
  The first OpenIDX sign-in with the same verified address links them; after
  that the local password can be retired.

## 4. Map roles and groups to ABP roles

`roles` holds the person's OpenIDX role names and `groups` their group names.
Map them in the same callback, after the user is found or created:

```csharp
var map = new Dictionary<string, string>
{
    ["finance-approvers"] = "FinanceApprover",
    ["app-admins"] = "admin",
};
var wanted = info.Principal.FindAll("groups").Select(c => c.Value)
    .Concat(info.Principal.FindAll("roles").Select(c => c.Value))
    .Where(map.ContainsKey).Select(n => map[n]).ToHashSet();
var current = await UserManager.GetRolesAsync(user);
await UserManager.AddToRolesAsync(user, wanted.Except(current));
await UserManager.RemoveFromRolesAsync(user, current.Intersect(map.Values).Except(wanted));
```

Only remove the ABP roles that the map manages, so roles granted inside the
application are left alone. ABP permissions stay on ABP roles.

## 5. Logout

- **RP-initiated:** `SignOutAsync("OpenIDX")` sends the browser to
  `/oauth/logout` with `id_token_hint` and the registered
  `post_logout_redirect_uri`. The OpenIDX session and the tokens it backs are
  revoked.
- **Back-channel:** OpenIDX POSTs a signed `logout_token`
  (`application/x-www-form-urlencoded`) to the registered back-channel URI
  when a session ends anywhere: a logout in another application, an
  administrator ending the session, offboarding. Validate it against the
  issuer's JWKS (`aud` is your client id, `events` names
  `http://schemas.openid.net/event/backchannel-logout`, there is no `nonce`),
  then end the ABP sessions whose `sid` matches. Store `sid` from the ID token
  at sign-in (`OnTokenValidated`) so you can find them.

See [OAuth 2.0 & OIDC](OAUTH-OIDC.md) for the logout token's contents and the
rules for `post_logout_redirect_uri`.

## 6. Redirect URIs per environment

Register every host the application answers on. Redirect URIs are matched
exactly.

| Environment | Redirect URI | Post-logout redirect URI |
| --- | --- | --- |
| On-premises | `https://app.tdv.local/signin-oidc` | `https://app.tdv.local/signout-callback-oidc` |
| Azure App Service | `https://<app>.azurewebsites.net/signin-oidc` | `https://<app>.azurewebsites.net/signout-callback-oidc` |
| Azure, custom domain | `https://app.tdv.org/signin-oidc` | `https://app.tdv.org/signout-callback-oidc` |

Behind a reverse proxy or App Service, make ASP.NET Core see the public
scheme and host (`app.UseForwardedHeaders()` with `XForwardedProto` and
`XForwardedHost`), or the handler builds an `http://` redirect URI that
OpenIDX refuses.

## 7. Publishing through the OpenIDX access proxy

An application that is not reachable from the internet can be published
through the OpenIDX access proxy instead of opening it. The proxy
signs the person in with OpenIDX before any request reaches the application,
and applies the application's access conditions on every request. With
*Require a fresh second factor* set, a page load whose login session has not
proved a second factor within the step-up window is sent through sign-in again
with `acr_values=urn:openidx:mfa:fresh` and back to the page. Keep the ABP
OIDC sign-in above as well: the proxy decides who may reach the application,
and ABP still needs to know who the user is.

## Checklist

- [ ] Application registered, PKCE required, redirect and post-logout URIs for
      every environment
- [ ] Assignment and access conditions set
- [ ] `acr_values` sent, and `acr` checked where a page needs more
- [ ] Linking by `sub`, and by e-mail only with `email_verified=true`
- [ ] Role and group mapping removes only the roles it manages
- [ ] Back-channel logout endpoint validates the logout token and ends
      sessions by `sid`
