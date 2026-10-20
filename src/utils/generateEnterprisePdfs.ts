import { PDFDocument, rgb, StandardFonts, PDFPage, PDFFont } from 'pdf-lib';

interface DocumentTemplate {
  filename: string;
  title: string;
  category: string;
  description: string;
  build: () => Promise<Buffer>;
}

// Colors
const COLOR_HEADER_BG = rgb(14 / 255, 20 / 255, 32 / 255);       // #0e1420
const COLOR_ACCENT = rgb(37 / 255, 99 / 255, 235 / 255);          // #2563eb
const COLOR_TEXT_MAIN = rgb(15 / 255, 23 / 255, 42 / 255);       // #0f172a
const COLOR_TEXT_MUTED = rgb(71 / 255, 85 / 255, 105 / 255);     // #475569
const COLOR_BORDER = rgb(226 / 255, 232 / 255, 240 / 255);       // #e2e8f0
const COLOR_TABLE_HDR = rgb(241 / 255, 245 / 255, 249 / 255);    // #f1f5f9
const COLOR_RED = rgb(220 / 255, 38 / 255, 38 / 255);            // #dc2626
const COLOR_GREEN = rgb(16 / 255, 185 / 255, 129 / 255);         // #10b981
const COLOR_WHITE = rgb(1, 1, 1);

function drawHeader(
  page: PDFPage,
  fontBold: PDFFont,
  fontRegular: PDFFont,
  leftTag: string,
  rightBadge: string,
  refId: string,
  badgeColor = COLOR_RED
) {
  const { width, height } = page.getSize();
  // Header background rectangle
  page.drawRectangle({
    x: 40,
    y: height - 60,
    width: width - 80,
    height: 32,
    color: COLOR_HEADER_BG,
  });

  // Cobalt accent bar
  page.drawRectangle({
    x: 40,
    y: height - 62,
    width: width - 80,
    height: 2,
    color: COLOR_ACCENT,
  });

  // Left Tag
  page.drawText(leftTag, {
    x: 52,
    y: height - 44,
    size: 9,
    font: fontBold,
    color: COLOR_WHITE,
  });

  // Ref ID in middle
  page.drawText(`REF: ${refId}`, {
    x: 270,
    y: height - 44,
    size: 8,
    font: fontRegular,
    color: rgb(148 / 255, 163 / 255, 184 / 255),
  });

  // Right badge text
  const badgeWidth = fontBold.widthOfTextAtSize(rightBadge, 8);
  page.drawRectangle({
    x: width - 52 - badgeWidth - 12,
    y: height - 52,
    width: badgeWidth + 12,
    height: 16,
    color: badgeColor,
  });

  page.drawText(rightBadge, {
    x: width - 52 - badgeWidth - 6,
    y: height - 44,
    size: 8,
    font: fontBold,
    color: COLOR_WHITE,
  });
}

function drawFooter(
  page: PDFPage,
  fontRegular: PDFFont,
  fontBold: PDFFont,
  pageNum: number,
  totalPages: number,
  refId: string
) {
  const { width } = page.getSize();
  // Divider line
  page.drawRectangle({
    x: 40,
    y: 45,
    width: width - 80,
    height: 1,
    color: COLOR_BORDER,
  });

  page.drawText('TRUSTVAULT ZERO-TRUST CRYPTOGRAPHIC VAULT • AES-256-GCM PROTECTED', {
    x: 40,
    y: 32,
    size: 7.5,
    font: fontBold,
    color: COLOR_TEXT_MUTED,
  });

  page.drawText(`Ref: ${refId} • Page ${pageNum} of ${totalPages}`, {
    x: width - 180,
    y: 32,
    size: 7.5,
    font: fontRegular,
    color: COLOR_TEXT_MUTED,
  });
}

function drawParagraph(
  page: PDFPage,
  text: string,
  startX: number,
  startY: number,
  maxWidth: number,
  font: PDFFont,
  size: number,
  color = COLOR_TEXT_MAIN,
  lineHeight = 14
): number {
  const words = text.split(' ');
  let line = '';
  let y = startY;

  for (const word of words) {
    const testLine = line.length === 0 ? word : `${line} ${word}`;
    const testWidth = font.widthOfTextAtSize(testLine, size);

    if (testWidth > maxWidth && line.length > 0) {
      page.drawText(line, { x: startX, y, size, font, color });
      y -= lineHeight;
      line = word;
    } else {
      line = testLine;
    }
  }

  if (line.length > 0) {
    page.drawText(line, { x: startX, y, size, font, color });
    y -= lineHeight;
  }

  return y;
}

function drawTable(
  page: PDFPage,
  startX: number,
  startY: number,
  colWidths: number[],
  headers: string[],
  rows: string[][],
  fontBold: PDFFont,
  fontRegular: PDFFont
): number {
  const tableWidth = colWidths.reduce((a, b) => a + b, 0);
  const rowHeight = 20;
  let y = startY;

  // Header row background
  page.drawRectangle({
    x: startX,
    y: y - rowHeight,
    width: tableWidth,
    height: rowHeight,
    color: COLOR_HEADER_BG,
  });

  // Header cells
  let currentX = startX;
  for (let i = 0; i < headers.length; i++) {
    page.drawText(headers[i], {
      x: currentX + 6,
      y: y - 14,
      size: 8,
      font: fontBold,
      color: COLOR_WHITE,
    });
    currentX += colWidths[i];
  }
  y -= rowHeight;

  // Data rows
  for (let r = 0; r < rows.length; r++) {
    const isAlt = r % 2 === 1;
    if (isAlt) {
      page.drawRectangle({
        x: startX,
        y: y - rowHeight,
        width: tableWidth,
        height: rowHeight,
        color: COLOR_TABLE_HDR,
      });
    }

    // Border line under row
    page.drawRectangle({
      x: startX,
      y: y - rowHeight,
      width: tableWidth,
      height: 0.5,
      color: COLOR_BORDER,
    });

    currentX = startX;
    for (let c = 0; c < rows[r].length; c++) {
      page.drawText(rows[r][c], {
        x: currentX + 6,
        y: y - 14,
        size: 7.5,
        font: c === 0 ? fontBold : fontRegular,
        color: COLOR_TEXT_MAIN,
      });
      currentX += colWidths[c];
    }
    y -= rowHeight;
  }

  return y;
}

function drawSignatureBlock(
  page: PDFPage,
  startY: number,
  party1Name: string,
  party1Title: string,
  party1Org: string,
  party2Name: string,
  party2Title: string,
  party2Org: string,
  dateStr: string,
  fontBold: PDFFont,
  fontRegular: PDFFont
): number {
  const { width } = page.getSize();
  const col1X = 40;
  const col2X = width / 2 + 20;
  const sigLineWidth = 210;

  let y = startY;

  // Sign lines
  page.drawRectangle({ x: col1X, y, width: sigLineWidth, height: 1, color: COLOR_TEXT_MAIN });
  page.drawRectangle({ x: col2X, y, width: sigLineWidth, height: 1, color: COLOR_TEXT_MAIN });

  y -= 14;
  page.drawText(`By: ${party1Name}`, { x: col1X, y, size: 9, font: fontBold, color: COLOR_TEXT_MAIN });
  page.drawText(`By: ${party2Name}`, { x: col2X, y, size: 9, font: fontBold, color: COLOR_TEXT_MAIN });

  y -= 12;
  page.drawText(`Title: ${party1Title}`, { x: col1X, y, size: 8, font: fontRegular, color: COLOR_TEXT_MUTED });
  page.drawText(`Title: ${party2Title}`, { x: col2X, y, size: 8, font: fontRegular, color: COLOR_TEXT_MUTED });

  y -= 12;
  page.drawText(`Entity: ${party1Org}`, { x: col1X, y, size: 8, font: fontRegular, color: COLOR_TEXT_MUTED });
  page.drawText(`Entity: ${party2Org}`, { x: col2X, y, size: 8, font: fontRegular, color: COLOR_TEXT_MUTED });

  y -= 12;
  page.drawText(`Date: ${dateStr}`, { x: col1X, y, size: 8, font: fontRegular, color: COLOR_TEXT_MUTED });
  page.drawText(`Date: ${dateStr}`, { x: col2X, y, size: 8, font: fontRegular, color: COLOR_TEXT_MUTED });

  y -= 20;
  page.drawRectangle({
    x: 40,
    y: y - 18,
    width: width - 80,
    height: 22,
    color: rgb(240 / 255, 253 / 255, 244 / 255), // light emerald
  });
  page.drawRectangle({
    x: 40,
    y: y - 18,
    width: width - 80,
    height: 1,
    color: COLOR_GREEN,
  });

  page.drawText('CRYPTOGRAPHICALLY VERIFIED & ANCHORED VIA TRUSTVAULT HMAC-SHA256 AUDIT LEDGER', {
    x: 52,
    y: y - 8,
    size: 7.5,
    font: fontBold,
    color: rgb(21 / 255, 128 / 255, 61 / 255), // dark emerald
  });

  return y - 24;
}

// ==========================================
// 1. MASTER SERVICES AGREEMENT (MSA)
// ==========================================
export async function buildMsaDocument(): Promise<Buffer> {
  const doc = await PDFDocument.create();
  const fontRegular = await doc.embedFont(StandardFonts.Helvetica);
  const fontBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const fontOblique = await doc.embedFont(StandardFonts.HelveticaOblique);

  const refId = 'TV-LEGAL-2026-08842';

  // --- PAGE 1 ---
  const p1 = doc.addPage([612, 792]);
  drawHeader(p1, fontBold, fontRegular, 'TRUSTVAULT LEGAL ARCHIVE', 'CONFIDENTIAL - PRIVILEGED', refId, COLOR_RED);

  let y = 710;
  p1.drawText('MASTER SERVICES AGREEMENT (MSA)', { x: 40, y, size: 18, font: fontBold, color: COLOR_HEADER_BG });
  y -= 16;
  p1.drawText('Enterprise Zero-Trust Cryptographic Services & Storage Agreement', {
    x: 40,
    y,
    size: 10,
    font: fontOblique,
    color: COLOR_ACCENT,
  });
  y -= 24;

  const recitals =
    'This Master Services Agreement ("Agreement") is made and entered into as of October 20, 2026 ("Effective Date"), by and between TrustVault Systems Inc., a Delaware corporation located at 100 Cryptography Way, Suite 400, San Francisco, CA 94105 ("TrustVault" or "Provider"), and Acme Corporation, a Delaware corporation having offices at 500 Market Street, New York, NY 10001 ("Acme" or "Client").';
  y = drawParagraph(p1, recitals, 40, y, 532, fontRegular, 9, COLOR_TEXT_MAIN, 13);
  y -= 12;

  // Section 1
  p1.drawText('1. SCOPE OF SERVICES & ZERO-TRUST DEPLOYMENT', { x: 40, y, size: 11, font: fontBold, color: COLOR_HEADER_BG });
  y -= 14;
  const s1_1 =
    '1.1 Platform Provisioning: Provider shall grant Client enterprise access to the TrustVault Cryptographic Document Vault. All documents stored under this Agreement are subject to automatic AES-256-GCM envelope encryption at rest, unique per-file initialization vectors (IVs), and 128-bit authentication tags.';
  y = drawParagraph(p1, s1_1, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 6;
  const s1_2 =
    '1.2 Multi-Factor Authentication: Mandatory TOTP (Time-based One-Time Password) 2FA enforcement is guaranteed for all administrative, document owner, and operational accounts, resisting credential-stuffing and session hijacking attacks.';
  y = drawParagraph(p1, s1_2, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 6;
  const s1_3 =
    '1.3 Single Gatekeeper Data Access Layer (DAL): All document operations (list, search, read, edit, delete, permission grant) are mediated through a centralized authorization gatekeeper that rejects unauthorized requests with HTTP 404 to eliminate existence oracles.';
  y = drawParagraph(p1, s1_3, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 12;

  // Section 2
  p1.drawText('2. SERVICE LEVEL AGREEMENT (SLA) & PERFORMANCE COMMITMENTS', {
    x: 40,
    y,
    size: 11,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const s2_1 =
    '2.1 High Availability: Provider guarantees a Monthly Uptime Percentage of at least 99.99% for all cryptographic storage and retrieval endpoints, excluding pre-announced maintenance windows.';
  y = drawParagraph(p1, s2_1, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 6;

  // SLA Table
  const slaHeaders = ['Service Tier', 'Target Availability', 'Key Rotation Latency', 'Critical Incident Response'];
  const slaRows = [
    ['Enterprise Tier-1', '99.99% Uptime', '< 50ms per key', '15 Minutes (24/7/365)'],
    ['Cryptographic Ledger', '100% Sequence Monotonicity', 'Synchronous Advisory Lock', 'Immediate PagerDuty Alert'],
    ['Snapshot DR Recovery', 'RPO = 0, RTO < 60 mins', 'Automated Verification', '1 Hour Maximum SLA']
  ];
  y = drawTable(p1, 40, y, [110, 110, 140, 172], slaHeaders, slaRows, fontBold, fontRegular);
  y -= 12;

  // Section 3
  p1.drawText('3. CLIENT DATA SOVEREIGNTY & ZERO-KNOWLEDGE CONSTRAINTS', {
    x: 40,
    y,
    size: 11,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const s3_1 =
    '3.1 Exclusive Ownership: Client retains sole title and intellectual property rights in all customer materials. Provider acquires no proprietary rights or license to Client documents beyond the operational mandate of secure vaulting.';
  y = drawParagraph(p1, s3_1, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);

  drawFooter(p1, fontRegular, fontBold, 1, 2, refId);

  // --- PAGE 2 ---
  const p2 = doc.addPage([612, 792]);
  drawHeader(p2, fontBold, fontRegular, 'TRUSTVAULT LEGAL ARCHIVE', 'CONFIDENTIAL - PRIVILEGED', refId, COLOR_RED);

  y = 710;
  // Section 4
  p2.drawText('4. CONFIDENTIALITY, GDPR & REGULATORY COMPLIANCE', {
    x: 40,
    y,
    size: 11,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const s4_1 =
    '4.1 Confidentiality Obligations: Each party covenants that it shall exercise at least reasonable care (and not less than the care used for its own confidential assets) to protect all confidential information from unauthorized inspection, disclosure, or distribution.';
  y = drawParagraph(p2, s4_1, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 6;
  const s4_2 =
    '4.2 Regulatory Standards: Provider shall maintain continuous compliance with SOC 2 Type II controls, ISO/IEC 27001:2022 certifications, and GDPR Article 32 cryptographic security requirements throughout the term of this Agreement.';
  y = drawParagraph(p2, s4_2, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 12;

  // Section 5
  p2.drawText('5. TERM, TERMINATION & NIST SP 800-88 CRYPTO-SHREDDING', {
    x: 40,
    y,
    size: 11,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const s5_1 =
    '5.1 Term: This Agreement shall remain in effect for an initial term of thirty-six (36) months from the Effective Date, automatically renewing for successive one (1) year terms unless either party provides sixty (60) days advance written notice of non-renewal.';
  y = drawParagraph(p2, s5_1, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 6;
  const s5_2 =
    '5.2 Secure Erasure: Upon termination or written customer request, Provider shall execute NIST SP 800-88 compliant cryptographic wiping, overwriting disk sectors with random entropy before unlinking storage handles to prevent forensic file recovery.';
  y = drawParagraph(p2, s5_2, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 12;

  // Section 6
  p2.drawText('6. INDEMNIFICATION & AGGREGATE LIABILITY', {
    x: 40,
    y,
    size: 11,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const s6_1 =
    '6.1 Liability Cap: To the maximum extent permitted by applicable law, direct liability arising under this Agreement shall be limited to two times (2x) the total fees paid by Client to Provider during the twelve (12) month period immediately preceding the triggering event.';
  y = drawParagraph(p2, s6_1, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 24;

  // Section 7: Signatures
  p2.drawText('IN WITNESS WHEREOF, the parties hereto have executed this Master Services Agreement.', {
    x: 40,
    y,
    size: 9.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 30;

  drawSignatureBlock(
    p2,
    y,
    'Alice Vance',
    'VP of Security & Infrastructure',
    'TrustVault Systems Inc.',
    'Bob Martinez',
    'Chief Information Security Officer (CISO)',
    'Acme Corporation',
    'October 20, 2026',
    fontBold,
    fontRegular
  );

  drawFooter(p2, fontRegular, fontBold, 2, 2, refId);

  return Buffer.from(await doc.save());
}

// ==========================================
// 2. EXECUTIVE COMPENSATION REVIEW Q3
// ==========================================
export async function buildExecutiveCompDocument(): Promise<Buffer> {
  const doc = await PDFDocument.create();
  const fontRegular = await doc.embedFont(StandardFonts.Helvetica);
  const fontBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const fontOblique = await doc.embedFont(StandardFonts.HelveticaOblique);

  const refId = 'TV-BOD-2026-COMP-Q3';

  // --- PAGE 1 ---
  const p1 = doc.addPage([612, 792]);
  drawHeader(p1, fontBold, fontRegular, 'TRUSTVAULT BOARD OF DIRECTORS', 'BOARD RESTRICTED // LEVEL 5', refId, COLOR_RED);

  let y = 710;
  p1.drawText('EXECUTIVE COMPENSATION REVIEW & EQUITY GRANT REPORT', {
    x: 40,
    y,
    size: 15,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 16;
  p1.drawText('Fiscal Year 2026 Third Quarter C-Suite Compensation & Performance Assessment', {
    x: 40,
    y,
    size: 9.5,
    font: fontOblique,
    color: COLOR_ACCENT,
  });
  y -= 22;

  const intro =
    'This Executive Compensation Review is submitted to the Board of Directors Compensation Committee pursuant to corporate governance guidelines. Compensation benchmark data was evaluated in partnership with Radford Global Tech and Bessemer Cloud Cybersecurity Executive Compensation Indexes (75th percentile market targeting).';
  y = drawParagraph(p1, intro, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 12;

  p1.drawText('1. EXECUTIVE BASE SALARY & INCENTIVE SCHEDULE (FY2026)', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;

  const compHeaders = ['Executive Officer', 'Base Salary', 'Target Incentive', 'Annual RSUs', 'Vesting Structure'];
  const compRows = [
    ['Chief Executive Officer (CEO)', '$450,000', '100% of Base', '120,000 RSUs', '4-Yr Monthly (1-Yr Cliff)'],
    ['Chief Technology Officer (CTO)', '$385,000', '80% of Base', '95,000 RSUs', '4-Yr Monthly (1-Yr Cliff)'],
    ['Chief Info Security Officer (CISO)', '$360,000', '75% of Base', '85,000 RSUs', '4-Yr Monthly (1-Yr Cliff)'],
    ['Chief Financial Officer (CFO)', '$350,000', '70% of Base', '75,000 RSUs', '4-Yr Monthly (1-Yr Cliff)'],
    ['VP Product Engineering', '$320,000', '60% of Base', '60,000 RSUs', '4-Yr Monthly (1-Yr Cliff)'],
  ];
  y = drawTable(p1, 40, y, [130, 80, 95, 95, 132], compHeaders, compRows, fontBold, fontRegular);
  y -= 14;

  p1.drawText('2. Q1-Q3 2026 CORPORATE PERFORMANCE METRIC ATTAINMENT', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;

  const kpiHeaders = ['Strategic Corporate KPI', 'Target Goal', 'Actual Q3 Outcome', 'Achievement Multiplier'];
  const kpiRows = [
    ['Annual Recurring Revenue (ARR)', '$42.0M', '$48.6M (+15.7%)', '115% Payout'],
    ['Zero-Trust Vault System Uptime', '99.99%', '99.994% Certified', '100% Payout'],
    ['SOC 2 Type II Certification', '0 Deficiencies', 'Clean Opinion Issued', '110% Payout'],
    ['Enterprise Logo Growth', '120 Accounts', '142 Accounts (+18%)', '118% Payout'],
  ];
  y = drawTable(p1, 40, y, [160, 100, 140, 132], kpiHeaders, kpiRows, fontBold, fontRegular);

  drawFooter(p1, fontRegular, fontBold, 1, 2, refId);

  // --- PAGE 2 ---
  const p2 = doc.addPage([612, 792]);
  drawHeader(p2, fontBold, fontRegular, 'TRUSTVAULT BOARD OF DIRECTORS', 'BOARD RESTRICTED // LEVEL 5', refId, COLOR_RED);

  y = 710;
  p2.drawText('3. DODD-FRANK SECTION 954 CLAWBACK POLICY & GOVERNANCE', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const clawback =
    'In accordance with SEC Rule 10D-1 and the Dodd-Frank Wall Street Reform and Consumer Protection Act, all incentive-based executive compensation granted under this program shall be subject to mandatory recovery ("clawback") in the event the company is required to prepare an accounting restatement due to material noncompliance with financial reporting requirements.';
  y = drawParagraph(p2, clawback, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 14;

  p2.drawText('4. PEER MARKET COMPARISON & EQUITY POOL DILUTION', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const dilution =
    'The total equity pool allocated for the FY2026 Executive Incentive Grant represents 2.8% of total outstanding common stock on a fully-diluted basis, remaining well below the 4.0% shareholder-approved annual dilution cap. Unvested grants are governed by standard double-trigger change-of-control acceleration provisions.';
  y = drawParagraph(p2, dilution, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 16;

  p2.drawText('5. COMPENSATION COMMITTEE RESOLUTION & APPROVAL', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const resolution =
    'RESOLVED, that the Board Compensation Committee hereby approves the executive compensation adjustments, bonus payouts, and RSU equity grants specified in Section 1, having determined that these arrangements align executive incentives with long-term enterprise shareholder value.';
  y = drawParagraph(p2, resolution, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 30;

  drawSignatureBlock(
    p2,
    y,
    'Eleanor Vance',
    'Chair, Compensation Committee',
    'TrustVault Holdings Inc. Board',
    'David Sterling',
    'Independent Director & Audit Chair',
    'TrustVault Holdings Inc. Board',
    'October 18, 2026',
    fontBold,
    fontRegular
  );

  drawFooter(p2, fontRegular, fontBold, 2, 2, refId);

  return Buffer.from(await doc.save());
}

// ==========================================
// 3. ZERO-TRUST ARCHITECTURE SPECIFICATION
// ==========================================
export async function buildZeroTrustSpecDocument(): Promise<Buffer> {
  const doc = await PDFDocument.create();
  const fontRegular = await doc.embedFont(StandardFonts.Helvetica);
  const fontBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const fontOblique = await doc.embedFont(StandardFonts.HelveticaOblique);

  const refId = 'TV-ARCH-SPEC-2026-V2';

  // --- PAGE 1 ---
  const p1 = doc.addPage([612, 792]);
  drawHeader(p1, fontBold, fontRegular, 'TRUSTVAULT TECHNICAL SPECIFICATION', 'ENGINEERING SPEC // PUBLIC', refId, COLOR_ACCENT);

  let y = 710;
  p1.drawText('ZERO-TRUST CRYPTOGRAPHIC VAULT ARCHITECTURE', {
    x: 40,
    y,
    size: 16,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 16;
  p1.drawText('Technical Specification: AES-256-GCM Envelope Encryption & HMAC Audit Chains', {
    x: 40,
    y,
    size: 9.5,
    font: fontOblique,
    color: COLOR_ACCENT,
  });
  y -= 22;

  const archIntro =
    'This specification defines the cryptographic foundations and zero-trust controls implemented in TrustVault. In conformance with NIST SP 800-207, perimeter-based security assumptions are eliminated in favor of continuous authentication, single-gatekeeper data access, and tamper-evident cryptographic ledgers.';
  y = drawParagraph(p1, archIntro, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 12;

  p1.drawText('1. ENVELOPE ENCRYPTION AT REST (AES-256-GCM)', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const envDesc =
    'Storage files are protected using authenticated AES-256 in Galois/Counter Mode (GCM). Disk blobs are packed with a standardized 45-byte envelope prefix before the ciphertext stream, ensuring physical disk theft yields only unrecoverable cryptographic noise:';
  y = drawParagraph(p1, envDesc, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 6;

  const encHeaders = ['Field Name', 'Byte Size', 'Offset', 'Description / Security Purpose'];
  const encRows = [
    ['Magic Header', '17 Bytes', '0 - 16', 'TV_AES256_GCM_v1: (Versioned format identifier)'],
    ['Initialization Vector', '12 Bytes', '17 - 28', 'Cryptographically secure random IV per file'],
    ['Authentication Tag', '16 Bytes', '29 - 44', '128-bit GCM MAC preventing ciphertext tampering'],
    ['Payload Ciphertext', 'N Bytes', '45 - EOF', 'Encrypted file body protected by master key'],
  ];
  y = drawTable(p1, 40, y, [110, 70, 70, 282], encHeaders, encRows, fontBold, fontRegular);
  y -= 14;

  p1.drawText('2. APPEND-ONLY IMMUTABLE AUDIT LEDGER (HMAC-SHA256)', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const auditDesc =
    'Every system event produces a continuous hash chain entry covering 13 canonical database columns. Monotonic ordering is protected against concurrent insertion races via PostgreSQL transaction advisory locking (Lock ID: 749281). External anchoring detects ledger truncation or head fork attacks.';
  y = drawParagraph(p1, auditDesc, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);

  drawFooter(p1, fontRegular, fontBold, 1, 2, refId);

  // --- PAGE 2 ---
  const p2 = doc.addPage([612, 792]);
  drawHeader(p2, fontBold, fontRegular, 'TRUSTVAULT TECHNICAL SPECIFICATION', 'ENGINEERING SPEC // PUBLIC', refId, COLOR_ACCENT);

  y = 710;
  p2.drawText('3. SINGLE GATEKEEPER DATA ACCESS LAYER (DAL)', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const dalDesc =
    'To eliminate Insecure Direct Object Reference (IDOR) vulnerabilities and authorization drift, all document queries are enforced through DocumentDAL.loadDocumentFor(). Unauthorized probes or expired grants return unified HTTP 404 responses rather than HTTP 403, eliminating document existence enumeration oracles (CWE-209).';
  y = drawParagraph(p2, dalDesc, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 12;

  p2.drawText('4. ADVANCED EPHEMERAL SHARING PROTOCOLS', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const shareHeaders = ['Protocol Feature', 'Enforcement Mechanism', 'Defense Against Loophole'];
  const shareRows = [
    ['Burn-on-Download (BOD)', 'Atomically revokes DB grant on download', 'Prevents token reuse & offline sharing'],
    ['Preview-Only Streaming', 'Blocks GET /download (403), allows canvas', 'Prevents raw binary exfiltration'],
    ['Time-Bounded Grants', 'Auto-expires via expiresAt UTC timestamp', 'Eliminates lingering access rights'],
    ['Crypto-Shredding', 'NIST SP 800-88 3-pass entropy wiping', 'Prevents forensic undelete of deleted files'],
  ];
  y = drawTable(p2, 40, y, [130, 190, 212], shareHeaders, shareRows, fontBold, fontRegular);
  y -= 16;

  p2.drawText('5. MULTI-FACTOR AUTHENTICATION & SESSION LIFECYCLE', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const mfaDesc =
    'TrustVault enforces RFC 6238 TOTP with replay attack defense: the last validated 30-second time-step is atomically recorded in the database, preventing token replay within the same time window. Demotions or privilege revocations immediately increment the user tokenVersion, terminating all existing JWT sessions globally.';
  y = drawParagraph(p2, mfaDesc, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 30;

  drawSignatureBlock(
    p2,
    y,
    'Alice Vance',
    'Lead Security Architect',
    'TrustVault Cryptography Group',
    'Dr. Julian Meyer',
    'Director of Cryptographic Research',
    'TrustVault Security Labs',
    'October 20, 2026',
    fontBold,
    fontRegular
  );

  drawFooter(p2, fontRegular, fontBold, 2, 2, refId);

  return Buffer.from(await doc.save());
}

// ==========================================
// 4. SOC 2 TYPE II COMPLIANCE REPORT
// ==========================================
export async function buildSoc2ReportDocument(): Promise<Buffer> {
  const doc = await PDFDocument.create();
  const fontRegular = await doc.embedFont(StandardFonts.Helvetica);
  const fontBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const fontOblique = await doc.embedFont(StandardFonts.HelveticaOblique);

  const refId = 'SOC2-2026-TV-TYP2';

  // --- PAGE 1 ---
  const p1 = doc.addPage([612, 792]);
  drawHeader(p1, fontBold, fontRegular, 'INDEPENDENT AUDITOR REPORT', 'AICPA SSAE 18 // ATTESTATION', refId, COLOR_GREEN);

  let y = 710;
  p1.drawText('INDEPENDENT SERVICE AUDITOR’S REPORT (SOC 2 TYPE II)', {
    x: 40,
    y,
    size: 15,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 16;
  p1.drawText('Report on Controls Relevant to Security, Confidentiality, and System Availability', {
    x: 40,
    y,
    size: 9.5,
    font: fontOblique,
    color: COLOR_ACCENT,
  });
  y -= 22;

  const auditIntro =
    'To the Board of Directors and Management of TrustVault Systems Inc.: We have examined TrustVault Systems Inc.’s description of its Zero-Trust Cryptographic Document Vault System throughout the period October 1, 2025 to September 30, 2026, and the suitability of the design and operating effectiveness of controls included in the description.';
  y = drawParagraph(p1, auditIntro, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 12;

  p1.drawText('1. SERVICE AUDITOR’S UNQUALIFIED OPINION', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const opinion =
    'In our opinion, in all material respects: (1) The description fairly presents the TrustVault Zero-Trust Platform system; (2) The controls stated were suitably designed to provide reasonable assurance that the service commitments were achieved; and (3) The controls tested operated effectively throughout the examination period without material deficiency.';
  y = drawParagraph(p1, opinion, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 14;

  p1.drawText('2. TRUST SERVICES CRITERIA EVALUATION SUMMARY', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;

  const socHeaders = ['Criteria', 'Control Description', 'Testing Result', 'Exceptions Noted'];
  const socRows = [
    ['CC6.1', 'Role-Based Access Control & DAL Gatekeeper', 'Tested 250 Access Grants', '0 Exceptions'],
    ['CC6.6', 'AES-256-GCM Encryption At Rest on Disk', 'Tested 100 Storage Blobs', '0 Exceptions'],
    ['CC6.7', 'TOTP Multi-Factor Authentication Enforcement', 'Tested 75 User Logins', '0 Exceptions'],
    ['CC7.2', 'HMAC-SHA256 Tamper-Evident Audit Ledger', 'Tested 2,500+ Sequential Logs', '0 Exceptions'],
    ['CC8.1', 'Cryptographic Key Lifecycle & Secure Deletion', 'Tested NIST Shredding API', '0 Exceptions'],
  ];
  y = drawTable(p1, 40, y, [60, 212, 160, 100], socHeaders, socRows, fontBold, fontRegular);

  drawFooter(p1, fontRegular, fontBold, 1, 2, refId);

  // --- PAGE 2 ---
  const p2 = doc.addPage([612, 792]);
  drawHeader(p2, fontBold, fontRegular, 'INDEPENDENT AUDITOR REPORT', 'AICPA SSAE 18 // ATTESTATION', refId, COLOR_GREEN);

  y = 710;
  p2.drawText('3. DETAILED PROCEDURES & CRYPTOGRAPHIC TEST RESULTS', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const procDesc =
    'Our examination included testing of automated system controls and cryptographic invariants. Specifically: (a) Physical disk inspections verified that raw files cannot be read without master key decryption; (b) Advisory lock evaluation proved zero race conditions or sequence discontinuities during high-concurrency audit logging; and (c) In-browser preview isolation prevented binary downloads on restricted preview grants.';
  y = drawParagraph(p2, procDesc, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 16;

  p2.drawText('4. AUDITOR INDEPENDENCE & PROFESSIONAL STANDARDS', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const stdDesc =
    'Our examination was conducted in accordance with attestation standards established by the American Institute of Certified Public Accountants (AICPA). Those standards require that we plan and perform the examination to obtain reasonable assurance about whether the system description is presented fairly and controls operated effectively.';
  y = drawParagraph(p2, stdDesc, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 30;

  drawSignatureBlock(
    p2,
    y,
    'Robert Sterling',
    'CPA, CISA, CISSP — Partner',
    'Grant Thornton & Associates LLP',
    'Sarah Jenkins',
    'Senior Cyber Audit Manager',
    'Grant Thornton & Associates LLP',
    'October 10, 2026',
    fontBold,
    fontRegular
  );

  drawFooter(p2, fontRegular, fontBold, 2, 2, refId);

  return Buffer.from(await doc.save());
}

// ==========================================
// 5. INCIDENT RESPONSE PLAN & RUNBOOK
// ==========================================
export async function buildIncidentResponseDocument(): Promise<Buffer> {
  const doc = await PDFDocument.create();
  const fontRegular = await doc.embedFont(StandardFonts.Helvetica);
  const fontBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const fontOblique = await doc.embedFont(StandardFonts.HelveticaOblique);

  const refId = 'TV-IRP-2026-REV4';

  // --- PAGE 1 ---
  const p1 = doc.addPage([612, 792]);
  drawHeader(p1, fontBold, fontRegular, 'OPERATIONAL RUNBOOK', 'INTERNAL OPERATIONS // RESTRICTED', refId, COLOR_RED);

  let y = 710;
  p1.drawText('INCIDENT RESPONSE & DISASTER RECOVERY RUNBOOK', {
    x: 40,
    y,
    size: 15,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 16;
  p1.drawText('Enterprise Standard Operating Procedure for Threat Containment & Key Rotation', {
    x: 40,
    y,
    size: 9.5,
    font: fontOblique,
    color: COLOR_ACCENT,
  });
  y -= 22;

  const irpIntro =
    'This Runbook establishes mandatory operational protocols for the containment of cryptographic anomalies, key compromise scenarios, and disaster recovery. All personnel with elevated vault privileges must maintain certified familiarity with these procedures.';
  y = drawParagraph(p1, irpIntro, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 12;

  p1.drawText('1. INCIDENT SEVERITY CLASSIFICATION & SLA MATRIX', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;

  const sevHeaders = ['Severity Level', 'Incident Definition', 'Response SLA', 'Escalation Target'];
  const sevRows = [
    ['SEV-1 (Critical)', 'Key Compromise, Ledger Discontinuity, Breach', '15 Minutes', 'Incident Commander & CISO'],
    ['SEV-2 (Major)', 'MFA Provider Outage, High Latency (>500ms)', '1 Hour', 'Lead Infrastructure Engineer'],
    ['SEV-3 (Moderate)', 'Single User Auth Failure, Queue Backlog', '4 Hours', 'On-Call Systems Engineer'],
    ['SEV-4 (Low)', 'Non-Security Bug, Documentation Update', '24 Hours', 'Engineering Team Lead'],
  ];
  y = drawTable(p1, 40, y, [90, 202, 100, 140], sevHeaders, sevRows, fontBold, fontRegular);
  y -= 14;

  p1.drawText('2. EMERGENCY STORAGE KEY ROTATION PROTOCOL', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const rotDesc =
    'Upon declaration of SEV-1 Key Compromise: (1) Freeze operational document writes via admin emergency control; (2) Generate new 256-bit AES master storage seed in secondary HSM partition; (3) Deploy background re-encryption worker to migrate active blobs to new envelope tags with zero downtime; (4) Shred retired keys.';
  y = drawParagraph(p1, rotDesc, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);

  drawFooter(p1, fontRegular, fontBold, 1, 2, refId);

  // --- PAGE 2 ---
  const p2 = doc.addPage([612, 792]);
  drawHeader(p2, fontBold, fontRegular, 'OPERATIONAL RUNBOOK', 'INTERNAL OPERATIONS // RESTRICTED', refId, COLOR_RED);

  y = 710;
  p2.drawText('3. DISASTER RECOVERY & DISK SHREDDING PROTOCOLS', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;
  const drDesc =
    'Recovery Point Objective (RPO) is zero seconds due to synchronous database transaction commits and write-through envelope encryption. Recovery Time Objective (RTO) is under 60 minutes for full snapshot restoration. All backup archives are signed with HMAC manifests and verified prior to restoration.';
  y = drawParagraph(p2, drDesc, 40, y, 532, fontRegular, 8.5, COLOR_TEXT_MAIN, 12);
  y -= 16;

  p2.drawText('4. 24/7 INCIDENT COMMAND TEAM & ESCALATION DIRECTORY', {
    x: 40,
    y,
    size: 10.5,
    font: fontBold,
    color: COLOR_HEADER_BG,
  });
  y -= 14;

  const contactHeaders = ['Role', 'Name', 'Primary Contact', '24/7 Emergency Line'];
  const contactRows = [
    ['Incident Commander', 'Alice Vance', 'alice@trustvault.local', '+1 (800) 555-8285 x101'],
    ['Lead Cryptographer', 'Dr. Julian Meyer', 'julian@trustvault.local', '+1 (800) 555-8285 x102'],
    ['CISO / External Liaison', 'Bob Martinez', 'bob@acme.corp', '+1 (800) 555-8285 x103'],
    ['General Legal Counsel', 'Sarah Sterling, Esq.', 'legal@trustvault.local', '+1 (800) 555-8285 x104'],
  ];
  y = drawTable(p2, 40, y, [110, 110, 150, 162], contactHeaders, contactRows, fontBold, fontRegular);
  y -= 30;

  drawSignatureBlock(
    p2,
    y,
    'Alice Vance',
    'Incident Commander & VP Security',
    'TrustVault Incident Response Team',
    'Bob Martinez',
    'Advisory Board Representative',
    'Client Security Council',
    'October 20, 2026',
    fontBold,
    fontRegular
  );

  drawFooter(p2, fontRegular, fontBold, 2, 2, refId);

  return Buffer.from(await doc.save());
}

export const ENTERPRISE_DOCUMENTS: DocumentTemplate[] = [
  {
    filename: 'MSA_Acme_2026.pdf',
    title: 'Master Services Agreement (MSA) - Acme Corp',
    category: 'Legal',
    description: 'Confidential enterprise MSA contract with Acme Corporation detailing SLA commitments and data sovereignty.',
    build: buildMsaDocument,
  },
  {
    filename: 'Executive_Comp_Q3.pdf',
    title: 'Executive Compensation Review Q3',
    category: 'Finance',
    description: 'Restricted board review of C-level compensation packages, equity grant schedules, and Dodd-Frank clawbacks.',
    build: buildExecutiveCompDocument,
  },
  {
    filename: 'Zero_Trust_Architecture_Spec.pdf',
    title: 'Zero-Trust Architecture Technical Specification',
    category: 'Security',
    description: 'Cryptographic specification detailing AES-256-GCM envelope encryption, HMAC-SHA256 audit chaining, and single-gatekeeper DAL.',
    build: buildZeroTrustSpecDocument,
  },
  {
    filename: 'SOC2_Type_II_Compliance_Report.pdf',
    title: 'SOC 2 Type II Independent Service Auditor’s Report',
    category: 'Compliance',
    description: 'Independent attestation report by Grant Thornton LLP verifying TrustVault security, confidentiality, and audit integrity controls.',
    build: buildSoc2ReportDocument,
  },
  {
    filename: 'Incident_Response_Plan_2026.pdf',
    title: 'FY2026 Global Enterprise Incident Response & Disaster Recovery Plan',
    category: 'Operations',
    description: 'Standard operating runbook for cryptographic key rotation, HSM failover procedures, and cyber incident containment.',
    build: buildIncidentResponseDocument,
  },
];
