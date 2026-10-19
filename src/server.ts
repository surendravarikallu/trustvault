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

export const app = express();

// 1. Reverse proxy configuration for Cloudflare Tunnel
app.set('trust proxy', 1);

// 2. Simple query parser to prevent Express qs nested object injection attacks
app.set('query parser', 'simple');

// 3. Security headers & CORS
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));

// 4. Global IP rate limiter: 100 requests per minute
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' }
});
app.use(globalLimiter);

// 5. JSON Body parsing with strict size limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// 6. Health check endpoint
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    system: 'TrustVault Zero-Trust Security Engine',
    timestamp: new Date().toISOString()
  });
});

// 7. Route registration
app.use('/api/auth', authRouter);
app.use('/api/documents', documentRouter);
app.use('/api/admin', adminRouter);

// 8. Serve built frontend SPA if frontend/dist exists
const frontendDist = path.resolve(__dirname, '../frontend/dist');
if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
  app.get('*', (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/storage') || path.extname(req.path)) {
      return next();
    }
    res.sendFile(path.join(frontendDist, 'index.html'));
  });
}

// 9. 404 Catch-all handler for API routes
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found.' });
});

// 10. Global Error handling middleware
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled server exception:', err);
  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({
    error: err.message || 'Internal server error.'
  });
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
