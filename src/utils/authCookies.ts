import { Response } from 'express';

export function setAuthCookies(res: Response, token: string): void {
  const isProd = process.env.NODE_ENV === 'production';
  const cookieOpts = {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax' as const,
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
    path: '/'
  };

  if (isProd) {
    res.cookie('__Host-trustvault_token', token, cookieOpts);
  }
  res.cookie('trustvault_token', token, cookieOpts);
}

export function clearAuthCookies(res: Response): void {
  res.clearCookie('__Host-trustvault_token', { path: '/' });
  res.clearCookie('trustvault_token', { path: '/' });
}
