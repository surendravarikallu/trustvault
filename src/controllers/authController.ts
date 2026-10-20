import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { Role } from '../dal/types';
import { config } from '../config';
import { AuthenticatedRequest } from '../middleware/auth';
import {
  getUserByEmail,
  getUserByEmailOrUsername,
  getUserById,
  createUser,
  incrementTokenVersion,
  lookupUserByExactEmail,
  setMfaPendingSecret
} from '../dal/userDal';
import QRCode from 'qrcode';
import { generateBase32Secret, generateTotpUri } from '../utils/totp';
import { encryptMfaSecret } from '../utils/mfaCrypto';

// Dummy hash generated with bcrypt 12 rounds for timing attack neutralization (L-08)
const DUMMY_BCRYPT_HASH = '$2b$12$e80yqV0rYyXq4r.15G8aTuOsqaVq6Vw5lZlOfeFm8Q1Vn6eYdKkhe';

const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().min(2, 'Name must be at least 2 characters')
});

const LoginSchema = z.object({
  email: z.string().min(1).optional(),
  username: z.string().min(1).optional(),
  usernameOrEmail: z.string().min(1).optional(),
  password: z.string().min(1),
  enrollMfa: z.boolean().optional()
}).refine(data => Boolean(data.email || data.username || data.usernameOrEmail), {
  message: 'Valid username or email is required.'
});

export async function register(req: Request, res: Response): Promise<void> {
  const parseResult = RegisterSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { email, password, name } = parseResult.data;

  const existingUser = await getUserByEmail(email);
  if (existingUser) {
    // Defense against Loophole L-09: Uniform generic message to prevent email harvesting
    res.status(400).json({ error: 'Registration request could not be processed.' });
    return;
  }

  const passwordHash = await bcrypt.hash(password, 12);
  // Default public registration strictly forces VIEWER role
  const newUser = await createUser({
    email,
    passwordHash,
    name,
    role: Role.VIEWER
  });

  const token = jwt.sign(
    { userId: newUser.id, tokenVersion: newUser.tokenVersion },
    config.jwtSecret,
    { algorithm: 'HS256', expiresIn: '8h' }
  );

  res.status(201).json({
    message: 'User registered successfully as VIEWER.',
    token,
    user: {
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      role: newUser.role
    }
  });
}

export async function login(req: Request, res: Response): Promise<void> {
  const parseResult = LoginSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: 'Valid username or email and password are required.' });
    return;
  }

  const { email, username, usernameOrEmail, password } = parseResult.data;
  const identifier = (email || username || usernameOrEmail || '').trim();
  const user = await getUserByEmailOrUsername(identifier);

  if (!user || !user.isActive) {
    // Defense against Loophole L-08: Execute dummy bcrypt compare to equalize response time
    await bcrypt.compare(password, DUMMY_BCRYPT_HASH);
    res.status(401).json({ error: 'Invalid username/email or password.' });
    return;
  }

  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordValid) {
    res.status(401).json({ error: 'Invalid username/email or password.' });
    return;
  }

  // Multi-Factor Authentication (RFC 6238 TOTP): Intercept credentials and require 2FA challenge
  if (user.mfaEnabled) {
    const mfaChallengeToken = jwt.sign(
      { userId: user.id, purpose: 'MFA_CHALLENGE' },
      config.jwtSecret,
      { algorithm: 'HS256', expiresIn: '3m' }
    );
    res.json({
      mfaRequired: true,
      mfaChallengeToken,
      message: 'MFA verification required. Please submit your 6-digit authenticator code or backup recovery code.'
    });
    return;
  }

  // Pre-Login / On-Demand Authenticator Registration Flow
  if (parseResult.data.enrollMfa) {
    const secret = generateBase32Secret(32);
    const serviceName = 'TrustVault';
    const otpauth = generateTotpUri(secret, user.email, serviceName);
    const qrCode = await QRCode.toDataURL(otpauth);
    const encryptedSecret = encryptMfaSecret(secret);
    await setMfaPendingSecret(user.id, encryptedSecret);

    const mfaEnrollToken = jwt.sign(
      { userId: user.id, purpose: 'MFA_ENROLL' },
      config.jwtSecret,
      { algorithm: 'HS256', expiresIn: '10m' }
    );

    res.json({
      mfaEnrollRequired: true,
      mfaEnrollToken,
      qrCode,
      secret,
      otpauthUrl: otpauth,
      message: 'Scan the QR code with Google Authenticator or Microsoft Authenticator, then submit the 6-digit code to complete login.'
    });
    return;
  }

  const token = jwt.sign(
    { userId: user.id, tokenVersion: user.tokenVersion },
    config.jwtSecret,
    { algorithm: 'HS256', expiresIn: '8h' }
  );

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      mfaEnabled: user.mfaEnabled
    }
  });
}

export async function logout(req: AuthenticatedRequest, res: Response): Promise<void> {
  if (!req.user) {
    res.status(401).json({ error: 'Not authenticated.' });
    return;
  }

  // Instant Revocation: Increment token version to kill all current user sessions (L-01)
  await incrementTokenVersion(req.user.id);
  res.json({ message: 'Logged out successfully. All active sessions invalidated.' });
}

export async function me(req: AuthenticatedRequest, res: Response): Promise<void> {
  if (!req.user) {
    res.status(401).json({ error: 'Not authenticated.' });
    return;
  }

  const fullUser = await getUserById(req.user.id);
  res.json({
    user: {
      ...req.user,
      mfaEnabled: fullUser?.mfaEnabled ?? false
    }
  });
}

export async function lookupUser(req: AuthenticatedRequest, res: Response): Promise<void> {
  const email = req.query.email as string;
  if (!email || typeof email !== 'string') {
    res.status(400).json({ error: 'Exact email query parameter is required.' });
    return;
  }

  const user = await lookupUserByExactEmail(email);
  if (!user) {
    res.status(404).json({ error: 'User not found.' });
    return;
  }

  res.json({ user });
}
