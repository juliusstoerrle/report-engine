# Report Engine: Frontend

Typescript-based web-application to select reports, provide parameters and download the final report.

## Authentication

All routes except `/healthz` and `/auth/*` require an authenticated session, backed by OpenID Connect on the
OAuth 2.1 profile via [`openid-client`](https://github.com/panva/node-openid-client): Authorization Code with
PKCE (S256), and the client authenticates to the token endpoint (and Keycloak's broker token endpoint) with a
short-lived JWT signed by its own private key (`private_key_jwt`, [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523))
rather than a shared client secret. Any OIDC-compliant identity provider supporting `private_key_jwt` works —
point `OIDC_ISSUER_URL` at one that serves a `/.well-known/openid-configuration` document. See
[.env.example](.env.example) for the required `OIDC_*` and `AUTH_*` variables.

This repo doesn't bundle an identity provider — point it at your own Keycloak (or other OIDC-compliant
provider) instance. Copy `.env.example` to `.env` and fill in `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_PRIVATE_KEY_FILE` (or `OIDC_CLIENT_PRIVATE_KEY`) and `AUTH_SESSION_SECRET`.

### Client key setup (Keycloak)

1. Generate a key: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out oidc-client-key.pem`
   (RSA keys work too and sign with RS256) and point `OIDC_CLIENT_PRIVATE_KEY_FILE` at it.
2. In the client's **Credentials** tab, set **Client Authenticator** to **Signed JWT** (signature algorithm
   `ES256`/`RS256` to match the key, or "any").
3. In the client's **Keys** tab, enable **Use JWKS URL** and set it to `https://<frontend-host>/auth/jwks`, which
   publishes only the public key. (Alternatively, import the public key/certificate there by hand.)
4. Remove the old `OIDC_CLIENT_SECRET` from the deployment — it is no longer read (startup fails with a pointer to
   the new variables if it is the only client credential set).

To rotate, replace the key file and restart; the key id defaults to the key's JWK thumbprint, so Keycloak
refetches the JWKS when it sees the new `kid`.
