import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { register, login, logout, me, lookupUser } from '../controllers/authController';
import { authenticate } from '../middleware/auth';

export const authRouter = Router();

// Rate limiter for authentication endpoints: 10 attempts per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again after 15 minutes.' }
});

authRouter.post('/register', authLimiter, register);
authRouter.post('/login', authLimiter, login);
authRouter.post('/logout', authenticate, logout);
authRouter.get('/me', authenticate, me);
authRouter.get('/lookup', authenticate, lookupUser);
