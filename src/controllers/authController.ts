import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { config } from '../config.js';
import { recordAudit } from '../services/auditService.js';

const prisma = new PrismaClient();

export async function register(req: Request, res: Response) {
  try {
    const { email, password, name, role } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }

    const existingUser = await prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() }
    });

    if (existingUser) {
      return res.status(409).json({ error: 'User with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const assignedRole = ['ADMIN', 'OWNER', 'VIEWER'].includes(role) ? role : 'VIEWER';

    const newUser = await prisma.user.create({
      data: {
        email: email.toLowerCase().trim(),
        passwordHash,
        name: name.trim(),
        role: assignedRole
      },
      select: { id: true, email: true, name: true, role: true, createdAt: true }
    });

    await recordAudit({
      action: 'LOGIN_SUCCESS',
      userId: newUser.id,
      userEmail: newUser.email,
      status: 'SUCCESS',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: `Account registered with role ${assignedRole}`
    });

    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, role: newUser.role },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn }
    );

    return res.status(201).json({
      message: 'User registered successfully.',
      user: newUser,
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Internal server error during registration.' });
  }
}

export async function login(req: Request, res: Response) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    if (!user) {
      await recordAudit({
        action: 'LOGIN_FAILED',
        userEmail: normalizedEmail,
        status: 'DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: 'Login attempt with unknown email'
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatch) {
      await recordAudit({
        action: 'LOGIN_FAILED',
        userId: user.id,
        userEmail: user.email,
        status: 'DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: 'Incorrect password entered'
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    await recordAudit({
      action: 'LOGIN_SUCCESS',
      userId: user.id,
      userEmail: user.email,
      status: 'SUCCESS',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: `Successful login for role ${user.role}`
    });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn }
    );

    return res.json({
      message: 'Login successful.',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Internal server error during login.' });
  }
}

export async function getMe(req: Request, res: Response) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  return res.json({ user: req.user });
}

export async function listAllUsers(req: Request, res: Response) {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, email: true, name: true, role: true }
    });
    return res.json({ users });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch users.' });
  }
}
