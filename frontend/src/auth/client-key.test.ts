import { createPublicKey, generateKeyPairSync, verify } from 'crypto';
import { loadClientSigningKey } from './client-key';

function pem(type: 'rsa' | 'ec', namedCurve?: string): string {
  const { privateKey } =
    type === 'rsa'
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : generateKeyPairSync('ec', { namedCurve: namedCurve! });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

test.each([
  ['rsa', undefined, 'RS256', 'RSA'],
  ['ec', 'P-256', 'ES256', 'EC'],
  ['ec', 'P-384', 'ES384', 'EC'],
] as const)('derives alg and a public-only JWK from a %s %s key', async (type, curve, alg, kty) => {
  const key = await loadClientSigningKey(pem(type, curve));

  expect(key.publicJwk).toMatchObject({ kty, alg, use: 'sig', kid: key.kid });
  expect(key.publicJwk).not.toHaveProperty('d');
  expect(key.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
});

test('uses an explicit kid when given', async () => {
  const key = await loadClientSigningKey(pem('ec', 'P-256'), 'my-key-1');
  expect(key.kid).toBe('my-key-1');
  expect(key.publicJwk.kid).toBe('my-key-1');
});

test('rejects unsupported key types', async () => {
  const { privateKey } = generateKeyPairSync('ed448');
  await expect(loadClientSigningKey(privateKey.export({ format: 'pem', type: 'pkcs8' }).toString())).rejects.toThrow(
    /Unsupported key type/,
  );
});

test('the private key signs what the published public JWK verifies', async () => {
  const key = await loadClientSigningKey(pem('ec', 'P-256'));
  const data = Buffer.from('header.payload');

  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, data);

  const publicKey = createPublicKey({ key: key.publicJwk, format: 'jwk' });
  expect(verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature))).toBe(true);
});
