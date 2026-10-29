import { createHash, createPrivateKey, createPublicKey, type webcrypto } from 'crypto';

export interface ClientSigningKey {
  readonly privateKey: CryptoKey;
  readonly kid: string;
  // The public half only - published at GET /auth/jwks so the identity provider can verify
  // client assertions without the key ever being uploaded/pasted anywhere by hand.
  readonly publicJwk: webcrypto.JsonWebKey & { kid: string; alg: string; use: 'sig' };
}

// Only EC P-384 / ES384 is accepted: one fixed algorithm keeps this (and the Keycloak client's
// "Signature algorithm" setting) unambiguous.
const ALG = 'ES384';
const CURVE = 'P-384';

// RFC 7638 JWK thumbprint - a stable, content-derived kid, so rotating the key file
// automatically yields a new kid without a separate setting to keep in sync.
function jwkThumbprint(jwk: webcrypto.JsonWebKey): string {
  const members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  return createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

/**
 * Loads the PEM-encoded private key this app authenticates to the identity provider with
 * (OAuth "private_key_jwt" client authentication, RFC 7523 - called "Signed JWT" in
 * Keycloak): only the public key ever leaves this app.
 */
export async function loadClientSigningKey(pem: string, kid?: string): Promise<ClientSigningKey> {
  const keyObject = createPrivateKey(pem);
  if (keyObject.asymmetricKeyType !== 'ec' || keyObject.asymmetricKeyDetails?.namedCurve !== 'secp384r1') {
    throw new Error(
      `The OIDC client key must be an EC ${CURVE} key, got ${keyObject.asymmetricKeyType} ` +
        `${keyObject.asymmetricKeyDetails?.namedCurve ?? ''}`.trim(),
    );
  }
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    keyObject.export({ format: 'der', type: 'pkcs8' }),
    { name: 'ECDSA', namedCurve: CURVE },
    false,
    ['sign'],
  );
  const publicJwk = createPublicKey(keyObject).export({ format: 'jwk' });
  const resolvedKid = kid ?? jwkThumbprint(publicJwk);

  return { privateKey, kid: resolvedKid, publicJwk: { ...publicJwk, kid: resolvedKid, alg: ALG, use: 'sig' } };
}
