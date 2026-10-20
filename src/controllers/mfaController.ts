import { Request, Response } from 'express';
import QRCode from 'qrcode';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { config } from '../config';
import { AuthenticatedRequest } from '../middleware/auth';
import {
  setMfaPendingSecret,
  enableMfa,
  disableMfa,
  getMfaState,
  recordMfaTimeStep,
  consumeMfaBackupCode,
  getUserById
} from '../dal/userDal';
import {
  encryptMfaSecret,
  decryptMfaSecret,
  getCurrentTotpTimeStep,
  generateBackupCodes
} from '../utils/mfaCrypto';
import {
  generateBase32Secret,
  generateTotpUri,
  verifyTOTP
} from '../utils/totp';
import { logAuditEvent } from '../services/auditService';
import { AuditStatus } from '../dal/types';

const VerifyTotpSchema = z.object({
  code: z.string().min(6).max(12)
});

const VerifyLoginSchema = z.object({
  mfaChallengeToken: z.string().min(10),
  code: z.string().min(6).max(12)
});

const DisableMfaSchema = z.object({
  password: z.string().min(1),
  code: z.string().min(6).max(12)
});

/**
 * Step 1: Initiate MFA Setup
 * Generates an encrypted secret and QR Code for authenticator apps.
 */
export async function setupMFA(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const dbUser = await getUserById(user.id);
  if (!dbUser) {
    res.status(404).json({ error: 'User not found.' });
    return;
  }

  const secret = generateBase32Secret(32);
  const serviceName = 'TrustVault';
  const otpauth = generateTotpUri(secret, dbUser.email, serviceName);
  const qrCodeDataUrl = await QRCode.toDataURL(otpauth);

  // Store encrypted secret in DB pending confirmation
  const encryptedSecret = encryptMfaSecret(secret);
  await setMfaPendingSecret(user.id, encryptedSecret);

  await logAuditEvent({
    action: 'MFA_SETUP_INITIATED',
    userId: user.id,
    userEmail: dbUser.email,
    status: AuditStatus.SUCCESS,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: 'User initiated MFA TOTP enrollment.'
  });

  res.json({
    message: 'Scan the QR code with your authenticator app (Google Authenticator, Authy, 1Password).',
    qrCode: qrCodeDataUrl,
    secret, // Raw Base32 key for manual entry
    otpauthUrl: otpauth
  });
}

/**
 * Step 2: Confirm MFA Enrollment
 * User submits the first 6-digit code to activate MFA and receive 8 backup codes.
 */
export async function verifySetupMFA(req: AuthenticatedRequest, res: Response): Promise<void> {
  const parseResult = VerifyTotpSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: 'Valid 6-digit verification code is required.' });
    return;
  }

  const { code } = parseResult.data;
  const user = req.user!;
  const mfaState = await getMfaState(user.id);

  // Validate that user initiated MFA setup and has an active pending encrypted secret
  if (!mfaState || !mfaState.mfaSecret) {
    res.status(400).json({ error: 'MFA setup has not been initiated. Please call /setup first.' });
    return;
  }

  let rawSecret: string;
  try {
    rawSecret = decryptMfaSecret(mfaState.mfaSecret);
  } catch {
    res.status(500).json({ error: 'Failed to decrypt MFA secret.' });
    return;
  }

  const result = verifyTOTP(code.trim(), rawSecret, 1);
  if (!result.valid) {
    await logAuditEvent({
      action: 'MFA_SETUP_VERIFICATION_FAILED',
      userId: user.id,
      userEmail: mfaState.email,
      status: AuditStatus.DENIED,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'Unknown',
      details: 'Invalid TOTP code supplied during MFA confirmation.'
    });
    res.status(400).json({ error: 'Invalid verification code. Please check your authenticator app time and try again.' });
    return;
  }

  const currentStep = getCurrentTotpTimeStep();
  const { rawCodes, hashedCodes } = generateBackupCodes();

  await enableMfa(user.id, hashedCodes, currentStep);

  await logAuditEvent({
    action: 'MFA_ENABLED',
    userId: user.id,
    userEmail: mfaState.email,
    status: AuditStatus.SUCCESS,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: 'Multi-Factor Authentication enabled with 8 single-use emergency backup codes.'
  });

  res.json({
    success: true,
    message: 'MFA successfully activated! Save your emergency backup recovery codes in a secure location.',
    backupCodes: rawCodes
  });
}

/**
 * Step 3: Complete Login Challenge with TOTP or Backup Code
 */
export async function verifyLoginMFA(req: Request, res: Response): Promise<void> {
  const parseResult = VerifyLoginSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: 'Valid challenge token and code are required.' });
    return;
  }

  const { mfaChallengeToken, code } = parseResult.data;

  let payload: any;
  try {
    payload = jwt.verify(mfaChallengeToken, config.jwtSecret, { algorithms: ['HS256'] });
  } catch {
    res.status(401).json({ error: 'Invalid or expired MFA challenge token.' });
    return;
  }

  if (payload.purpose !== 'MFA_CHALLENGE' || !payload.userId) {
    res.status(401).json({ error: 'Invalid challenge token purpose.' });
    return;
  }

  const mfaState = await getMfaState(payload.userId);
  if (!mfaState || !mfaState.mfaEnabled || !mfaState.mfaSecret) {
    res.status(400).json({ error: 'MFA is not enabled for this account.' });
    return;
  }

  const rawSecret = decryptMfaSecret(mfaState.mfaSecret);
  const currentStep = getCurrentTotpTimeStep();
  const normalizedCode = code.trim().replace(/\s+/g, '');

  let isVerified = false;
  let usedBackupCode = false;

  // 1. Check TOTP Code
  if (/^\d{6}$/.test(normalizedCode)) {
    const verifyResult = verifyTOTP(normalizedCode, rawSecret, 1);
    if (verifyResult.valid) {
      const codeStep = BigInt(verifyResult.step);

      // Replay Attack Defense (CWE-287 / RFC 6238 Sec 5.2):
      // Prevent reusing any code from an already verified or earlier time step
      if (mfaState.mfaLastTimeStep && mfaState.mfaLastTimeStep >= codeStep) {
        await logAuditEvent({
          action: 'MFA_REPLAY_ATTACK_BLOCKED',
          userId: mfaState.id,
          userEmail: mfaState.email,
          status: AuditStatus.DENIED,
          ipAddress: req.ip || '127.0.0.1',
          userAgent: req.headers['user-agent'] || 'Unknown',
          details: 'Attacker attempted to replay TOTP code from an already consumed time step.'
        });
        res.status(401).json({ error: 'TOTP code has already been used. Please wait for the next 30-second code.' });
        return;
      }

      isVerified = true;
      await recordMfaTimeStep(mfaState.id, codeStep);
    }
  }

  // 2. If TOTP failed, check single-use recovery backup codes
  if (!isVerified && mfaState.mfaBackupCodes && mfaState.mfaBackupCodes.length > 0) {
    const candidateHash = crypto.createHash('sha256').update(normalizedCode.toUpperCase()).digest('hex');
    if (mfaState.mfaBackupCodes.includes(candidateHash)) {
      isVerified = true;
      usedBackupCode = true;
      await consumeMfaBackupCode(mfaState.id, candidateHash);
    }
  }

  if (!isVerified) {
    await logAuditEvent({
      action: 'MFA_LOGIN_FAILED',
      userId: mfaState.id,
      userEmail: mfaState.email,
      status: AuditStatus.DENIED,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'Unknown',
      details: 'Invalid TOTP or backup code presented during MFA challenge.'
    });
    res.status(401).json({ error: 'Invalid authentication code or backup recovery code.' });
    return;
  }

  // Log successful login
  await logAuditEvent({
    action: usedBackupCode ? 'MFA_BACKUP_CODE_CONSUMED' : 'MFA_LOGIN_SUCCESS',
    userId: mfaState.id,
    userEmail: mfaState.email,
    status: AuditStatus.SUCCESS,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: usedBackupCode ? 'MFA login completed via single-use backup code.' : 'MFA login completed via TOTP code.'
  });

  // Issue full 8-hour session token
  const token = jwt.sign(
    { userId: mfaState.id, tokenVersion: mfaState.tokenVersion },
    config.jwtSecret,
    { algorithm: 'HS256', expiresIn: '8h' }
  );

  res.json({
    token,
    user: {
      id: mfaState.id,
      email: mfaState.email,
      name: mfaState.name,
      role: mfaState.role,
      mfaEnabled: true
    }
  });
}

/**
 * Step 4: Disable MFA
 * Requires password re-authentication and a valid TOTP code.
 */
export async function disableMFAHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const parseResult = DisableMfaSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: 'Password and current verification code are required to disable MFA.' });
    return;
  }

  const { password, code } = parseResult.data;
  const user = req.user!;
  const dbUser = await getUserById(user.id);
  const mfaState = await getMfaState(user.id);

  if (!dbUser || !mfaState || !mfaState.mfaEnabled || !mfaState.mfaSecret) {
    res.status(400).json({ error: 'MFA is not enabled on this account.' });
    return;
  }

  const isPasswordValid = await bcrypt.compare(password, dbUser.passwordHash);
  if (!isPasswordValid) {
    res.status(401).json({ error: 'Invalid password.' });
    return;
  }

  const rawSecret = decryptMfaSecret(mfaState.mfaSecret);
  const verifyResult = verifyTOTP(code.trim(), rawSecret, 1);

  if (!verifyResult.valid) {
    res.status(400).json({ error: 'Invalid TOTP code. MFA could not be disabled.' });
    return;
  }

  await disableMfa(user.id);

  await logAuditEvent({
    action: 'MFA_DISABLED',
    userId: user.id,
    userEmail: dbUser.email,
    status: AuditStatus.SUCCESS,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: 'MFA disabled with valid dual verification (password + TOTP).'
  });

  res.json({
    success: true,
    message: 'MFA has been disabled. Previous sessions invalidated.'
  });
}

/**
 * Confirm MFA Enrollment from Login Flow
 * Accepts an mfaEnrollToken + 6-digit code, activates MFA, and logs the user in.
 */
export async function confirmEnrollMFA(req: Request, res: Response): Promise<void> {
  const { mfaEnrollToken, code } = req.body;
  if (!mfaEnrollToken || !code || typeof code !== 'string') {
    res.status(400).json({ error: 'mfaEnrollToken and 6-digit verification code are required.' });
    return;
  }

  let payload: any;
  try {
    payload = jwt.verify(mfaEnrollToken, config.jwtSecret, { algorithms: ['HS256'] });
    if (payload.purpose !== 'MFA_ENROLL') {
      res.status(401).json({ error: 'Invalid challenge token purpose.' });
      return;
    }
  } catch {
    res.status(401).json({ error: 'Enrollment token has expired. Please log in again.' });
    return;
  }

  const userId = payload.userId;
  const mfaState = await getMfaState(userId);
  if (!mfaState || !mfaState.mfaSecret) {
    res.status(400).json({ error: 'MFA setup not found. Please restart enrollment.' });
    return;
  }

  const rawSecret = decryptMfaSecret(mfaState.mfaSecret);
  const verifyResult = verifyTOTP(code.trim(), rawSecret, 1);
  if (!verifyResult.valid) {
    res.status(400).json({ error: 'Invalid verification code. Please check your authenticator app.' });
    return;
  }

  const currentStep = getCurrentTotpTimeStep();
  const { rawCodes, hashedCodes } = generateBackupCodes();

  await enableMfa(userId, hashedCodes, currentStep);

  const dbUser = await getUserById(userId);
  const token = jwt.sign(
    { userId: dbUser!.id, tokenVersion: dbUser!.tokenVersion },
    config.jwtSecret,
    { algorithm: 'HS256', expiresIn: '8h' }
  );

  await logAuditEvent({
    action: 'MFA_ENROLLED_AND_CONFIRMED',
    userId: dbUser!.id,
    userEmail: dbUser!.email,
    status: AuditStatus.SUCCESS,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: 'User successfully enrolled Google/Microsoft Authenticator and activated MFA.'
  });

  res.json({
    message: 'Two-factor authentication successfully enabled!',
    token,
    user: {
      id: dbUser!.id,
      email: dbUser!.email,
      name: dbUser!.name,
      role: dbUser!.role
    },
    backupCodes: rawCodes
  });
}
