import {
  allowInsecureRequests,
  ClientAuth,
  Configuration,
  customFetch,
  discovery,
  type DiscoveryRequestOptions,
  PrivateKeyJwt,
} from 'openid-client';
import { AppConfig } from '../config';
import { withBackendHost } from './backend-host';
import { ClientSigningKey } from './client-key';

export async function createOidcClient(config: AppConfig['auth'], clientKey: ClientSigningKey): Promise<Configuration> {
  const issuerUrl = new URL(config.issuerUrl);

  const options: DiscoveryRequestOptions = {};

  // Plain-HTTP issuers only occur in local dev (see .env.local), where no
  // trusted TLS cert is available for the docker-internal Keycloak host.
  if (issuerUrl.protocol === 'http:') {
    options.execute = [allowInsecureRequests];
  }

  // The OIDC issuer identity is one fixed value per realm — it's baked into
  // every token's iss claim, so Keycloak can't present a different hostname
  // to this backend than it does to the browser. In local dev the issuer is
  // "localhost" (what the browser needs for the login redirect), which this
  // container can't reach as itself. When set, OIDC_BACKEND_HOST rewrites
  // only the network destination of outgoing requests to somewhere this
  // container can actually reach — the URLs used for discovery/issuer
  // validation are untouched, so they still match what Keycloak reports.
  if (config.backendHost) {
    const backendHost = config.backendHost;
    options[customFetch] = (url, init) => {
      const target = withBackendHost(new URL(url), backendHost);
      // CustomFetchOptions.body (FetchBody) isn't structurally identical to
      // DOM's BodyInit (e.g. Uint8Array vs ArrayBufferView), though the
      // runtime fetch accepts it fine — openid-client's own examples cast
      // through this same gap.
      return fetch(target, init as RequestInit);
    };
  }

  // private_key_jwt client authentication (RFC 7523): no shared client secret - each token
  // request carries a short-lived assertion signed with clientKey, whose public half the
  // identity provider fetches from GET /auth/jwks. Authorization Code + PKCE (S256) in
  // auth-router.ts plus this asymmetric client authentication is the OAuth 2.1 profile.
  return discovery(
    issuerUrl,
    config.clientId,
    { token_endpoint_auth_method: 'private_key_jwt' },
    clientAuthFor(clientKey),
    options,
  );
}

export function clientAuthFor(key: ClientSigningKey): ClientAuth {
  return PrivateKeyJwt({ key: key.privateKey, kid: key.kid });
}

/**
 * Adds a freshly signed client assertion (client_id, client_assertion_type, client_assertion)
 * to a form body, for token-endpoint-style requests openid-client doesn't make itself (e.g.
 * Keycloak's broker token endpoint) - the same assertion openid-client sends to the token endpoint.
 */
export async function authenticateClient(
  configuration: Configuration,
  key: ClientSigningKey,
  body: URLSearchParams,
): Promise<void> {
  // ClientAuth is typed as returning void, but PrivateKeyJwt's implementation is async (it signs).
  await clientAuthFor(key)(configuration.serverMetadata(), configuration.clientMetadata(), body, new Headers());
}
