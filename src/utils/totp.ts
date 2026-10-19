import crypto from 'crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodes an RFC 4648 Base32 string into a Buffer.
 */
export function base32Decode(base32: string): Buffer {
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  const clean = base32.toUpperCase().replace(/[\s=-]/g, '');

  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) {
      throw new Error(`Invalid base32 character: ${clean[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}

/**
 * Generates a cryptographically random Base32 secret string.
 */
export function generateBase32Secret(length = 32): string {
  const bytes = crypto.randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += BASE32_ALPHABET[bytes[i] % 32];
  }
  return result;
}

/**
 * Computes an RFC 6238 6-digit TOTP code for a given Base32 secret and time step.
 */
export function generateTOTP(
  secret: string,
  timeStep = Math.floor(Date.now() / 30000)
): string {
  const key = base32Decode(secret);
  const buffer = Buffer.alloc(8);
  buffer.writeBigInt64BE(BigInt(timeStep));

  const hmac = crypto.createHmac('sha1', key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;

  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const code = (binary % 1000000).toString().padStart(6, '0');
  return code;
}

/**
 * Verifies an RFC 6238 TOTP code against a secret with clock-drift tolerance.
 * window = 1 allows verification across current step and ±30 seconds (standard).
 */
export function verifyTOTP(
  token: string,
  secret: string,
  window = 1
): { valid: boolean; delta: number; step: number } {
  const normalized = token.trim();
  if (!/^\d{6}$/.test(normalized)) {
    return { valid: false, delta: 0, step: 0 };
  }

  const currentStep = Math.floor(Date.now() / 30000);

  for (let delta = -window; delta <= window; delta++) {
    const candidateStep = currentStep + delta;
    if (generateTOTP(secret, candidateStep) === normalized) {
      return { valid: true, delta, step: candidateStep };
    }
  }

  return { valid: false, delta: 0, step: 0 };
}

/**
 * Generates an otpauth:// URI for QR codes.
 */
export function generateTotpUri(
  secret: string,
  label: string,
  issuer = 'TrustVault'
): string {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedLabel = encodeURIComponent(label);
  return `otpauth://totp/${encodedIssuer}:${encodedLabel}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}
