import { createPublicKey, generateKeyPairSync, verify } from 'crypto';
import { loadClientSigningKey } from './client-key';

function pem(privateKey: { export(options: { format: 'pem'; type: 'pkcs8' }): string | Buffer }): string {
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

const P384_PEM = pem(generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey);

test('derives an ES384 public-only JWK with a thumbprint kid from a P-384 key', async () => {
  const key = await loadClientSigningKey(P384_PEM);

  expect(key.publicJwk).toMatchObject({ kty: 'EC', crv: 'P-384', alg: 'ES384', use: 'sig', kid: key.kid });
  expect(key.publicJwk).not.toHaveProperty('d');
  expect(key.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
});

test('uses an explicit kid when given', async () => {
  const key = await loadClientSigningKey(P384_PEM, 'my-key-1');
  expect(key.kid).toBe('my-key-1');
  expect(key.publicJwk.kid).toBe('my-key-1');
});

test.each([
  ['an RSA key', () => generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey],
  ['a P-256 key', () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey],
  ['an Ed25519 key', () => generateKeyPairSync('ed25519').privateKey],
])('rejects %s', async (_, generate) => {
  await expect(loadClientSigningKey(pem(generate()))).rejects.toThrow(/must be an EC P-384 key/);
});

test('the private key signs what the published public JWK verifies', async () => {
  const key = await loadClientSigningKey(P384_PEM);
  const data = Buffer.from('header.payload');

  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, key.privateKey, data);

  const publicKey = createPublicKey({ key: key.publicJwk, format: 'jwk' });
  expect(verify('sha384', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature))).toBe(true);
});
