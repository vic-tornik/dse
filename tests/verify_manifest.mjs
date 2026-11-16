// Independent canonicalization and Ed25519 verification for the local DCF profile.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(
      k => JSON.stringify(k) + ':' + canonical(value[k])
    ).join(',') + '}';
  }
  return JSON.stringify(value);
}

const [, , path, publicKey] = process.argv;
const { signatures, ...manifest } = JSON.parse(readFileSync(path, 'utf8'));
const digest = createHash('sha256').update(canonical(manifest)).digest();
const input = Buffer.concat([Buffer.from('DSE-DCF/1\0'), digest]);
const key = createPublicKey({key: {kty: 'OKP', crv: 'Ed25519', x: publicKey}, format: 'jwk'});
if (!verify(null, input, key, Buffer.from(signatures[0].signature, 'base64url'))) {
  throw Error('Independent signature verification failed');
}
