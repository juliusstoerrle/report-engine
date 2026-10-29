import { createHash, createPrivateKey, createPublicKey, type KeyObject, type webcrypto } from 'crypto';

export interface ClientSigningKey {
  readonly privateKey: CryptoKey;
  readonly kid: string;
  // The public half only - published at GET /auth/jwks so the identity provider can verify
  // client assertions without the key ever being uploaded/pasted anywhere by hand.
  readonly publicJwk: webcrypto.JsonWebKey & { kid: string; alg: string; use: 'sig' };
}

// JWS algorithm and the matching WebCrypto import parameters, per supported key type/curve.
// RSA keys use RS256 since it's the one RSA client-assertion algorithm every OAuth server
// (Keycloak's "Signed JWT" authenticator included) accepts by default.
function signingAlgorithm(key: KeyObject): { alg: string; webCrypto: RsaHashedImportParams | EcKeyImportParams } {
  switch (key.asymmetricKeyType) {
    case 'rsa':
      return { alg: 'RS256', webCrypto: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } };
    case 'ec': {
      const curve = key.asymmetricKeyDetails?.namedCurve;
      if (curve === 'prime256v1') {
        return { alg: 'ES256', webCrypto: { name: 'ECDSA', namedCurve: 'P-256' } };
      }
      if (curve === 'secp384r1') {
        return { alg: 'ES384', webCrypto: { name: 'ECDSA', namedCurve: 'P-384' } };
      }
      throw new Error(`Unsupported EC curve for the OIDC client key: ${curve}`);
    }
    default:
      throw new Error(`Unsupported key type for the OIDC client key: ${key.asymmetricKeyType} (use RSA or EC)`);
  }
}

// RFC 7638 JWK thumbprint - a stable, content-derived kid, so rotating the key file
// automatically yields a new kid without a separate setting to keep in sync.
function jwkThumbprint(jwk: webcrypto.JsonWebKey): string {
  const members =
    jwk.kty === 'RSA' ? { e: jwk.e, kty: jwk.kty, n: jwk.n } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  return createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

/**
 * Loads the PEM-encoded private key this app authenticates to the identity provider with
 * (OAuth "private_key_jwt" client authentication, RFC 7523 - called "Signed JWT" in
 * Keycloak), replacing a shared client secret: only the public key ever leaves this app.
 */
export async function loadClientSigningKey(pem: string, kid?: string): Promise<ClientSigningKey> {
  const keyObject = createPrivateKey(pem);
  const { alg, webCrypto } = signingAlgorithm(keyObject);
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    keyObject.export({ format: 'der', type: 'pkcs8' }),
    webCrypto,
    false,
    ['sign'],
  );
  const publicJwk = createPublicKey(keyObject).export({ format: 'jwk' });
  const resolvedKid = kid ?? jwkThumbprint(publicJwk);

  return { privateKey, kid: resolvedKid, publicJwk: { ...publicJwk, kid: resolvedKid, alg, use: 'sig' } };
}
