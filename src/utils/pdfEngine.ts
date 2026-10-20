import { PDFDocument, rgb, degrees, StandardFonts } from 'pdf-lib';
// @ts-ignore - pure JS lightweight package
import { encryptPDF } from '@pdfsmaller/pdf-encrypt-lite';
import crypto from 'crypto';

export interface WatermarkOptions {
  recipientEmail: string;
  ipAddress?: string;
  downloadedAt?: string;
  grantId?: string;
  customText?: string;
}

/**
 * Applies a diagonal, semi-transparent forensic watermark to all pages of a PDF document.
 * Defends against unauthorized screenshots, leak attribution evasion, and physical camera captures.
 */
export async function applyForensicWatermark(
  pdfBuffer: Buffer,
  options: WatermarkOptions
): Promise<Buffer> {
  const pdfDoc = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });
  const font = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const pages = pdfDoc.getPages();

  const timestamp = options.downloadedAt || new Date().toISOString();
  const primaryLine = options.customText
    ? `RESTRICTED: ${options.customText}`
    : `CONFIDENTIAL • AUTHORIZED RECIPIENT: ${options.recipientEmail}`;
  const secondaryLine = `IP: ${options.ipAddress || 'SECURE_CHANNEL'} • TIME: ${timestamp}${options.grantId ? ` • ID: ${options.grantId.slice(0, 8)}` : ''}`;

  for (const page of pages) {
    const { width, height } = page.getSize();
    const fontSize = Math.max(10, Math.min(width, height) / 38);

    // Diagonal angle across the page
    const rotationAngle = degrees(40);

    // Primary watermark line (center)
    page.drawText(primaryLine, {
      x: width * 0.12,
      y: height * 0.48,
      size: fontSize,
      font,
      color: rgb(0.8, 0.1, 0.1),
      opacity: 0.18,
      rotate: rotationAngle
    });

    // Secondary watermark line (under center)
    page.drawText(secondaryLine, {
      x: width * 0.14,
      y: height * 0.43,
      size: fontSize * 0.75,
      font,
      color: rgb(0.2, 0.2, 0.2),
      opacity: 0.18,
      rotate: rotationAngle
    });

    // Top and bottom security perimeter notices
    page.drawText(`TRUSTVAULT ZERO-TRUST CRYPTOGRAPHIC VAULT • LICENSED TO ${options.recipientEmail.toUpperCase()}`, {
      x: 30,
      y: height - 20,
      size: 8,
      font,
      color: rgb(0.5, 0.5, 0.5),
      opacity: 0.3
    });

    page.drawText(`DO NOT REDISTRIBUTE • TRACE ID: ${crypto.createHash('sha256').update(options.recipientEmail + timestamp).digest('hex').slice(0, 16)}`, {
      x: 30,
      y: 15,
      size: 8,
      font,
      color: rgb(0.5, 0.5, 0.5),
      opacity: 0.3
    });
  }

  const modifiedBytes = await pdfDoc.save();
  return Buffer.from(modifiedBytes);
}

/**
 * Dynamically encrypts a PDF with an ISO-compliant User Open Password.
 * Any PDF reader (Acrobat, Chrome, Apple Preview) prompts for this exact password to view.
 */
export async function protectPdfWithPassword(
  pdfBuffer: Buffer,
  userPassword: string,
  ownerPassword?: string
): Promise<Buffer> {
  const effectiveOwnerPw = ownerPassword || crypto.randomBytes(16).toString('hex');
  const encryptedUint8 = await encryptPDF(new Uint8Array(pdfBuffer), userPassword, effectiveOwnerPw);
  return Buffer.from(encryptedUint8);
}

/**
 * Generates an 8-character high-entropy alphanumeric One-Time Password (OTP).
 */
export function generatePdfOtp(): string {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excludes ambiguous 0, O, 1, I
  let otp = '';
  const randomBytes = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) {
    otp += charset[randomBytes[i] % charset.length];
  }
  return otp;
}
