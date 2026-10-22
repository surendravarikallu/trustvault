import { Response } from 'express';

export function setAuthCookies(res: Response, token: string): void {
  res.cookie('__Host-trustvault_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
    path: '/'
  });
}

export function clearAuthCookies(res: Response): void {
  res.clearCookie('__Host-trustvault_token', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/'
  });
}

