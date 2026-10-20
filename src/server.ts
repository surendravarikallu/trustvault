import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { config } from './config';
import { authRouter } from './routes/authRoutes';
import { documentRouter } from './routes/documentRoutes';
import { adminRouter } from './routes/adminRoutes';

import { pingDatabaseHealth } from './dal/backupDal';

export const app = express();

// 1. Reverse proxy configuration for Cloudflare Tunnel (1 hop)
app.set('trust proxy', 1);

// 2. Simple query parser to prevent Express qs nested object injection attacks
app.set('query parser', 'simple');

// 3. Security headers & CORS with Cloudflare Edge support
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        fontSrc: ["'self'", 'https:', 'data:'],
        formAction: ["'self'"],
        frameAncestors: ["'self'"],
        imgSrc: ["'self'", 'data:', 'blob:', 'https://challenges.cloudflare.com'],
        objectSrc: ["'self'", 'blob:'],
        frameSrc: ["'self'", 'blob:', 'https://challenges.cloudflare.com'],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://static.cloudflareinsights.com',
          'https://challenges.cloudflare.com'
        ],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
        connectSrc: [
          "'self'",
          'https://cloudflareinsights.com',
          'https://static.cloudflareinsights.com',
          'https://challenges.cloudflare.com'
        ],
        upgradeInsecureRequests: []
      }
    }
  })
);
app.use(cors({ origin: true, credentials: true }));

// 4. Global IP rate limiter: 100 requests per minute
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' }
});
app.use(globalLimiter);

// 5. JSON Body parsing with strict size limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// 6. Deep health check endpoint with database probe & system metrics
app.get('/api/health', async (_req: Request, res: Response) => {
  let dbStatus = 'connected';
  let dbLatencyMs = 0;

  try {
    const dbPing = await pingDatabaseHealth();
    dbLatencyMs = dbPing.latencyMs;
  } catch {
    dbStatus = 'disconnected';
  }

  const mem = process.memoryUsage();
  const isHealthy = dbStatus === 'connected';

  res.status(isHealthy ? 200 : 503).json({
    status: isHealthy ? 'healthy' : 'degraded',
    system: 'TrustVault Zero-Trust Security Engine',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    database: {
      status: dbStatus,
      latencyMs: dbLatencyMs
    },
    memory: {
      rssMb: Math.round((mem.rss / 1024 / 1024) * 100) / 100,
      heapUsedMb: Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100,
      heapTotalMb: Math.round((mem.heapTotal / 1024 / 1024) * 100) / 100
    }
  });
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
  const PORT = config.port;
  // Strictly bind to 127.0.0.1 (targets Cloudflare Tunnel ingress)
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`=======================================================`);
    console.log(` TrustVault Security Engine running on 127.0.0.1:${PORT}`);
    console.log(` Environment: ${config.nodeEnv}`);
    console.log(` Ingress: Bound to loopback for Cloudflare Tunnel`);
    console.log(`=======================================================`);
  });
}
