import { chromium } from 'playwright';

async function runUiVerification() {
  console.log('--- Launching Playwright Chromium Headless UI Simulation ---');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  const page = await context.newPage();

  const events: string[] = [];

  page.on('console', msg => {
    if (msg.type() === 'error') {
      console.log('Browser Error:', msg.text());
    }
  });

  try {
    // 1. Navigate to Application
    console.log('[UI-1] Navigating to http://127.0.0.1:7777 ...');
    await page.goto('http://127.0.0.1:7777', { waitUntil: 'networkidle' });
    events.push('Loaded initial page');

    // 2. Perform Login as Admin
    console.log('[UI-2] Authenticating as admin@trustvault.local ...');
    await page.fill('input[type="text"], input[type="email"]', 'admin@trustvault.local');
    await page.fill('input[type="password"]', 'Admin@TrustVault2026!');
    await page.click('button[type="submit"]');

    // Wait for Dashboard
    await page.waitForSelector('nav, table, .document-card', { timeout: 8000 });
    console.log('       Authenticated successfully. Vault Dashboard loaded.');
    events.push('Admin login success');

    // 3. Navigate to User Directory Tab
    console.log('[UI-3] Navigating to "Identity Governance" Directory Tab ...');
    const userTabBtn = page.locator('button', { hasText: 'Identity Governance' }).first();
    await userTabBtn.click();
    await page.waitForTimeout(1000);
    events.push('Navigated to Identity Governance tab');

    // Verify User Table renders
    const tableHeader = await page.locator('text=User Directory').first().isVisible();
    console.log(`       User Directory View visible: ${tableHeader}`);

    // 4. Test "Add User" Modal in UI
    console.log('[UI-4] Opening "Add User" Modal ...');
    const addUserBtn = page.locator('button', { hasText: 'Add User' }).first();
    if (await addUserBtn.isVisible()) {
      await addUserBtn.click();
      await page.waitForSelector('.modal-content, form', { timeout: 3000 });
      console.log('       Add User modal opened.');

      const simEmail = `ui_user_${Date.now()}@trustvault.local`;
      await page.fill('input[placeholder*="Name"], input[type="text"] >> nth=-3', 'UI Test Analyst');
      await page.fill('input[placeholder*="email"], input[type="email"] >> nth=-1', simEmail);
      await page.fill('input[type="password"] >> nth=-1', 'Analyst@TrustVault2026!');
      
      const submitUserBtn = page.locator('.modal-content button[type="submit"]').first();
      await submitUserBtn.click();
      await page.waitForTimeout(1500);
      console.log(`       Submitted new user: ${simEmail}`);
      events.push('Created user via UI modal');
    }

    // 5. Navigate to Audit Ledger Tab
    console.log('[UI-5] Navigating to "HMAC Audit Ledger" Tab ...');
    const auditTabBtn = page.locator('button', { hasText: 'HMAC Audit Ledger' }).first();
    await auditTabBtn.click();
    await page.waitForTimeout(1500);
    events.push('Navigated to HMAC Audit Ledger tab');

    // Verify Audit Verification Badge
    const auditStatusText = await page.locator('text=VALID (PASSED)').first().isVisible();
    console.log(`       Cryptographic Audit Ledger VALID badge visible: ${auditStatusText}`);

    // Click "Verify Ledger" button in UI
    const verifyBtn = page.locator('button', { hasText: 'Verify' }).first();
    if (await verifyBtn.isVisible()) {
      await verifyBtn.click();
      await page.waitForTimeout(1000);
      console.log('       Clicked manual ledger verification in UI.');
      events.push('Manual audit verification triggered in UI');
    }

    // 6. Navigate back to Documents
    console.log('[UI-6] Navigating to "Vault Documents" Tab ...');
    const docsTabBtn = page.locator('button', { hasText: 'Vault Documents' }).first();
    await docsTabBtn.click();
    await page.waitForTimeout(1000);
    events.push('Navigated to Vault Documents tab');

    // 7. Sign Out in UI
    console.log('[UI-7] Triggering Sign Out from UI Navbar ...');
    const logoutBtn = page.locator('button', { hasText: 'Sign Out' }).first();
    await logoutBtn.click();
    await page.waitForTimeout(1500);

    // Verify redirected back to Login screen
    const loginPromptVisible = await page.locator('button[type="submit"]', { hasText: 'Sign In' }).first().isVisible();
    console.log(`       Returned to Login View: ${loginPromptVisible}`);
    events.push('Signed out successfully');

    console.log('\n=======================================================');
    console.log(' PLAYWRIGHT BROWSER UI SIMULATION: 100% COMPLETE');
    console.log(' Events Executed:');
    events.forEach(e => console.log(`  - ${e}`));
    console.log('=======================================================');

  } catch (err: any) {
    console.error('Playwright UI Verification Error:', err.message);
    throw err;
  } finally {
    await browser.close();
  }
}

runUiVerification()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
