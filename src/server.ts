import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { csrfProtection } from './middleware/csrf';
import { config } from './config';
import { authRouter } from './routes/authRoutes';
import { documentRouter } from './routes/documentRoutes';
import { adminRouter } from './routes/adminRoutes';

import { pingDatabaseHealth } from './dal/backupDal';
import { prisma } from './prisma';

export const app = express();

/**
 * Asserts that the active database connection does not possess superuser,
 * createdb, or createrole privileges. Refuses server boot if true.
 */
export async function assertNonPrivilegedRuntimeRole(): Promise<void> {
  const result: any = await prisma.$queryRawUnsafe(
    'SELECT current_user AS role_name, (rolsuper OR rolcreatedb OR rolcreaterole) AS is_privileged FROM pg_roles WHERE rolname = current_user'
  );
  if (result?.[0]?.is_privileged) {
    throw new Error(
      `CRITICAL SECURITY VIOLATION: Refusing to start server. The application database connection is running as privileged role '${result[0].role_name}' (rolsuper, rolcreatedb, or rolcreaterole is true). Production runtime must connect via the least-privileged 'trustvault_app' role.`
    );
  }
}

// 1. Reverse proxy configuration for Cloudflare Tunnel (1 hop)
app.set('trust proxy', 1);

// 2. Simple query parser to prevent Express qs nested object injection attacks
app.set('query parser', 'simple');

// 3. Strict Security Headers: Frameguard DENY, Strict CSP, No CORS (Pure same-origin)
app.use(
  helmet({
    frameguard: { action: 'deny' },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        fontSrc: ["'self'", 'data:'],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
        scriptSrc: ["'self'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'"],
        upgradeInsecureRequests: []
      }
    }
  })
);
// Zero CORS: Application is strictly same-origin. Disallow external origin reflection.
app.use(cookieParser());
app.use(csrfProtection);

// Enforce no-store on all API endpoints to prevent intermediate proxy/browser caching of authenticated data
app.use('/api', (_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// 4. Global IP rate limiter: Configurable threshold, bypasses internal health probes
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX || '10000', 10),
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/health' || req.path === '/api/health/',
  message: { error: 'Too many requests. Please slow down.' }
});
app.use(globalLimiter);

// 5. JSON Body parsing with strict size limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// 6. Public health check endpoint: Returns minimal status without leaking internal metrics or marketing names
app.get('/api/health', async (_req: Request, res: Response) => {
  try {
    await pingDatabaseHealth();
    res.status(200).json({ status: 'ok' });
  } catch {
    res.status(503).json({ status: 'error' });
  }
});

// 7. Route registration
app.use('/api/auth', authRouter);
app.use('/api/documents', documentRouter);
app.use('/api/admin', adminRouter);

// 8. Serve built frontend SPA if frontend/dist exists
const frontendDist = fs.existsSync(path.resolve(process.cwd(), 'frontend/dist'))
  ? path.resolve(process.cwd(), 'frontend/dist')
  : path.resolve(__dirname, '../../frontend/dist');

if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
  app.get('*', (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/storage') || path.extname(req.path)) {
      return next();
    }
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.sendFile(path.join(frontendDist, 'index.html'));
  });
}

// 9. 404 Catch-all handler for API routes
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found.' });
});

// 10. Global Error handling middleware
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  const statusCode = err.statusCode || err.status || 500;
  if (statusCode >= 500) {
    console.error('Unhandled server exception:', err);
  }
  const message = (statusCode === 500 && config.nodeEnv === 'production')
    ? 'Internal server error.'
    : (err.message || 'Internal server error.');
  res.status(statusCode).json({ error: message });
});

// Start server if executed directly
if (require.main === module) {
  const startServer = async () => {
    if (config.nodeEnv === 'production') {
      await assertNonPrivilegedRuntimeRole();
    }
    const PORT = config.port;
    // Strictly bind to 127.0.0.1 (targets Cloudflare Tunnel ingress)
    app.listen(PORT, '127.0.0.1', () => {
      console.log(`=======================================================`);
      console.log(` TrustVault Security Engine running on 127.0.0.1:${PORT}`);
      console.log(` Environment: ${config.nodeEnv}`);
      console.log(` Ingress: Bound to loopback for Cloudflare Tunnel`);
      console.log(` Database Role: Non-privileged runtime enforced`);
      console.log(`=======================================================`);
    });
  };

  startServer().catch((err) => {
    console.error('FATAL: Server boot aborted due to security assertion:', err.message);
    process.exit(1);
  });
}
