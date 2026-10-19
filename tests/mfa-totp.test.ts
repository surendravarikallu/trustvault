import request from 'supertest';
import { app } from '../src/server';
import { generateTOTP } from '../src/utils/totp';

describe('Multi-Factor Authentication (MFA / TOTP) Enterprise Suite', () => {
  const testUser = {
    email: 'mfa_tester@trustvault.local',
    password: 'MfaTester2026!Secure',
    name: 'MFA Tester Account'
  };

  let authToken: string;
  let mfaSecret: string;
  let backupCodes: string[];

  beforeAll(async () => {
    // 1. Register test user
    await request(app)
      .post('/api/auth/register')
      .send(testUser);

    // 2. Initial login (before MFA enabled)
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: testUser.email, password: testUser.password });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.token).toBeDefined();
    expect(loginRes.body.mfaRequired).toBeUndefined();
    authToken = loginRes.body.token;
  });

  it('MFA-01: Initiating setup generates Base32 secret and QR code data URL', async () => {
    const res = await request(app)
      .post('/api/auth/mfa/setup')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body.secret).toBeDefined();
    expect(res.body.secret.length).toBeGreaterThanOrEqual(16);
    expect(res.body.qrCode).toMatch(/^data:image\/png;base64,/);
    expect(res.body.otpauthUrl).toContain('otpauth://totp/TrustVault');

    mfaSecret = res.body.secret;
  });

  it('MFA-02: Submitting an invalid 6-digit TOTP code during confirmation is rejected with HTTP 400', async () => {
    const res = await request(app)
      .post('/api/auth/mfa/verify-setup')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ code: '000000' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Invalid verification code');
  });

  it('MFA-03: Submitting genuine TOTP code activates MFA and returns 8 single-use recovery backup codes', async () => {
    const validTotp = generateTOTP(mfaSecret);

    const res = await request(app)
      .post('/api/auth/mfa/verify-setup')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ code: validTotp });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.backupCodes)).toBe(true);
    expect(res.body.backupCodes.length).toBe(8);

    backupCodes = res.body.backupCodes;
  });

  it('MFA-04: Login for MFA-enabled user intercepts credentials and returns restricted mfaChallengeToken', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: testUser.email, password: testUser.password });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.mfaRequired).toBe(true);
    expect(loginRes.body.mfaChallengeToken).toBeDefined();
    expect(loginRes.body.token).toBeUndefined();

    // Verify restricted challenge token cannot access protected document routes
    const docProbe = await request(app)
      .get('/api/documents')
      .set('Authorization', `Bearer ${loginRes.body.mfaChallengeToken}`);

    // Must be rejected because challenge token has no session credentials
    expect(docProbe.status).toBe(401);
  });

  it('MFA-05: Submitting valid TOTP completes challenge and grants full 8-hour session token', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: testUser.email, password: testUser.password });

    const challengeToken = loginRes.body.mfaChallengeToken;
    const validTotp = generateTOTP(mfaSecret);

    const verifyRes = await request(app)
      .post('/api/auth/mfa/verify-login')
      .send({
        mfaChallengeToken: challengeToken,
        code: validTotp
      });

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.token).toBeDefined();
    expect(verifyRes.body.user.email).toBe(testUser.email);
  });

  it('MFA-06: Replay Defense (CWE-287): Reusing the exact same TOTP code in the same 30s step is rejected', async () => {
    // Generate fresh challenge
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: testUser.email, password: testUser.password });

    const challengeToken = loginRes.body.mfaChallengeToken;
    const validTotp = generateTOTP(mfaSecret);

    // First attempt already succeeded in MFA-05; second attempt in same step must fail with 401
    const replayRes = await request(app)
      .post('/api/auth/mfa/verify-login')
      .send({
        mfaChallengeToken: challengeToken,
        code: validTotp
      });

    expect(replayRes.status).toBe(401);
    expect(replayRes.body.error).toContain('already been used');
  });

  it('MFA-07: Single-use emergency backup recovery code completes login and is burned from database', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: testUser.email, password: testUser.password });

    const challengeToken = loginRes.body.mfaChallengeToken;
    const chosenBackupCode = backupCodes[0];

    // First use: must succeed
    const firstUseRes = await request(app)
      .post('/api/auth/mfa/verify-login')
      .send({
        mfaChallengeToken: challengeToken,
        code: chosenBackupCode
      });

    expect(firstUseRes.status).toBe(200);
    expect(firstUseRes.body.token).toBeDefined();

    // Second use of the exact same backup code on a new challenge: MUST FAIL
    const secondLoginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: testUser.email, password: testUser.password });

    const secondChallengeToken = secondLoginRes.body.mfaChallengeToken;

    const secondUseRes = await request(app)
      .post('/api/auth/mfa/verify-login')
      .send({
        mfaChallengeToken: secondChallengeToken,
        code: chosenBackupCode
      });

    expect(secondUseRes.status).toBe(401);
    expect(secondUseRes.body.error).toContain('Invalid authentication code');
  });

  it('MFA-08: Disabling MFA requires dual verification (password + TOTP); invalidates sessions on success', async () => {
    // Acquire a fresh session token using another backup code
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: testUser.email, password: testUser.password });

    const sessionRes = await request(app)
      .post('/api/auth/mfa/verify-login')
      .send({
        mfaChallengeToken: loginRes.body.mfaChallengeToken,
        code: backupCodes[1]
      });

    const activeSessionToken = sessionRes.body.token;

    // Attempt to disable with wrong password: must fail
    const wrongPassRes = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Authorization', `Bearer ${activeSessionToken}`)
      .send({ password: 'WrongPassword!', code: generateTOTP(mfaSecret) });

    expect(wrongPassRes.status).toBe(401);

    // Disable with correct password and valid TOTP: must succeed
    const disableRes = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Authorization', `Bearer ${activeSessionToken}`)
      .send({ password: testUser.password, code: generateTOTP(mfaSecret) });

    expect(disableRes.status).toBe(200);
    expect(disableRes.body.success).toBe(true);

    // Subsequent login now bypasses MFA (returns session token immediately)
    const subsequentLogin = await request(app)
      .post('/api/auth/login')
      .send({ email: testUser.email, password: testUser.password });

    expect(subsequentLogin.status).toBe(200);
    expect(subsequentLogin.body.token).toBeDefined();
    expect(subsequentLogin.body.mfaRequired).toBeUndefined();
  });
});
