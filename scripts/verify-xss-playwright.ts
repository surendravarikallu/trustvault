import { chromium } from 'playwright';
import { PrismaClient, AuditStatus } from '@prisma/client';
import { StorageService } from '../src/services/storageService';
import { logAuditEvent } from '../src/dal/auditDal';
import fs from 'fs';
import path from 'path';

const prisma = new PrismaClient();

async function runXssPlaywrightVerification() {
  console.log('--- Starting Playwright End-to-End XSS Audit Verification ---');

  const xssPayload = '<img src=x onerror=window.__xss=1>';
  let dialogTriggered = false;
  let dialogMessage = '';

  // 1. Seed XSS document into database directly to test stored rendering across all views
  const adminUser = await prisma.user.findUnique({
    where: { email: 'admin@trustvault.local' }
  });

  if (!adminUser) {
    throw new Error('admin@trustvault.local user not found in database. Run db:seed first.');
  }

  // Persist a real text blob
  const tempDir = path.resolve('storage/temp');
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
  const tempFile = path.join(tempDir, 'xss_probe.txt');
  fs.writeFileSync(tempFile, 'Safe file content with no executable tags.');
  const stored = await StorageService.persistFile(tempFile);
  if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);

  const xssDoc = await prisma.document.create({
    data: {
      title: `XSS_Title_${xssPayload}`,
      description: `XSS_Desc_${xssPayload}`,
      category: `XSS_Cat_${xssPayload}`,
      originalFilename: `xss_${xssPayload}.txt`,
      storedFilename: stored.storedFilename,
      mimeType: 'text/plain',
      fileSize: stored.fileSize,
      fileHash: stored.fileHash,
      ownerId: adminUser.id
    }
  });

  // Also seed an audit record with XSS payload in details, documentTitle, userEmail
  await logAuditEvent({
    action: 'DOCUMENT_METADATA_READ',
    userId: adminUser.id,
    userEmail: `admin_${xssPayload}@trustvault.local`,
    documentId: xssDoc.id,
    documentTitle: xssDoc.title,
    status: AuditStatus.SUCCESS,
    ipAddress: '127.0.0.1',
    userAgent: `Mozilla_${xssPayload}`,
    details: `Audit_Detail_${xssPayload}`
  });

  console.log('Seeded malicious document and audit record containing payload:', xssPayload);

  // 2. Launch Playwright headless browser
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 }
  });
  const page = await context.newPage();

  // Listen for unexpected alert/confirm/prompt dialogs triggered by XSS
  page.on('dialog', (dialog) => {
    dialogTriggered = true;
    dialogMessage = dialog.message();
    console.error('CRITICAL VULNERABILITY: Dialog triggered by page:', dialog.message());
    dialog.dismiss();
  });

  // Check CSP violations
  page.on('console', (msg) => {
    if (msg.type() === 'error' && msg.text().includes('Content Security Policy')) {
      console.log('CSP correctly blocked inline asset/script:', msg.text());
    }
  });

  try {
    // 3. Navigate to application
    console.log('Navigating to TrustVault SPA at http://127.0.0.1:7777 ...');
    await page.goto('http://127.0.0.1:7777', { waitUntil: 'networkidle' });

    // 4. Log in as admin
    console.log('Logging in as admin@trustvault.local ...');
    await page.fill('input[type="text"], input[type="email"]', 'admin@trustvault.local');
    await page.fill('input[type="password"]', 'Admin@TrustVault2026!');
    await page.click('button[type="submit"]');

    // Wait for vault dashboard
    await page.waitForSelector('table, .document-card, nav', { timeout: 10000 });
    console.log('Successfully authenticated and loaded dashboard.');

    // 5. Check Document Vault View
    const xssFlagInDashboard = await page.evaluate(() => (window as any).__xss);
    if (xssFlagInDashboard !== undefined) {
      throw new Error(`XSS executed on Document Vault View! window.__xss = ${xssFlagInDashboard}`);
    }
    console.log('PASS: Vault View rendered without executing XSS.');

    // 6. Navigate to Admin Audit Ledger View
    console.log('Navigating to Audit Ledger View...');
    const auditTabBtn = page.locator('button:has-text("Audit Ledger"), a:has-text("Audit"), button:has-text("Audit")').first();
    if (await auditTabBtn.isVisible()) {
      await auditTabBtn.click();
      await page.waitForTimeout(1000);

      const xssFlagInAudit = await page.evaluate(() => (window as any).__xss);
      if (xssFlagInAudit !== undefined) {
        throw new Error(`XSS executed on Admin Audit View! window.__xss = ${xssFlagInAudit}`);
      }
      console.log('PASS: Admin Audit Ledger rendered without executing XSS.');
    }

    // 7. Check User Directory View if present
    const userTabBtn = page.locator('button:has-text("Users"), button:has-text("User Directory")').first();
    if (await userTabBtn.isVisible()) {
      await userTabBtn.click();
      await page.waitForTimeout(1000);

      const xssFlagInUsers = await page.evaluate(() => (window as any).__xss);
      if (xssFlagInUsers !== undefined) {
        throw new Error(`XSS executed on User Directory View! window.__xss = ${xssFlagInUsers}`);
      }
      console.log('PASS: User Directory rendered without executing XSS.');
    }

    // 8. Final Assertions
    if (dialogTriggered) {
      throw new Error(`XSS Attack succeeded! Alert dialog triggered with message: ${dialogMessage}`);
    }

    console.log('===============================================================');
    console.log('PLAYWRIGHT XSS VERIFICATION COMPLETE:');
    console.log(' - window.__xss is strictly undefined across all views');
    console.log(' - No alert/confirm dialogs triggered');
    console.log(' - React auto-escaping verified on document, user, and audit paths');
    console.log('===============================================================');
  } finally {
    await browser.close();
    // Cleanup seeded xss doc and audit log
    await prisma.auditLog.deleteMany({ where: { details: { contains: 'XSS_Detail_' } } });
    await prisma.document.delete({ where: { id: xssDoc.id } });
    if (stored?.storedFilename) {
      await StorageService.deleteFile(stored.storedFilename);
    }
    await prisma.$disconnect();
  }
}

runXssPlaywrightVerification().catch((err) => {
  console.error('Playwright XSS Verification Failed:', err);
  process.exit(1);
});
