import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { register, login, logout, me, lookupUser } from '../controllers/authController';
import {
  setupMFA,
  verifySetupMFA,
  verifyLoginMFA,
  disableMFAHandler,
  confirmEnrollMFA
} from '../controllers/mfaController';
import { authenticate } from '../middleware/auth';

export const authRouter = Router();

// Rate limiter for authentication endpoints: 300 attempts per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again after 15 minutes.' }
});

// Rate limiter for TOTP verification: 150 attempts per 15 minutes
const mfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many MFA verification attempts. Please wait 15 minutes.' }
});

authRouter.post('/register', authLimiter, register);
authRouter.post('/login', authLimiter, login);
authRouter.post('/logout', authenticate, logout);
authRouter.get('/me', authenticate, me);
authRouter.get('/lookup', authenticate, lookupUser);

// MFA Endpoints
authRouter.post('/mfa/setup', authenticate, setupMFA);
authRouter.post('/mfa/verify-setup', authenticate, verifySetupMFA);
authRouter.post('/mfa/verify-login', mfaLimiter, verifyLoginMFA);
authRouter.post('/mfa/confirm-enroll', mfaLimiter, confirmEnrollMFA);
authRouter.post('/mfa/disable', authenticate, disableMFAHandler);
