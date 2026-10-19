import fs from 'fs';
import path from 'path';
import { config } from '../config';

export interface AuditAnchor {
  sequenceNumber: string;
  headHash: string;
  timestamp: string;
  exportedAt: string;
}

/**
 * Atomically exports the latest audit ledger head to storage/audit_anchor.json.
 * Defense against Loophole L-13: Audit Tail Truncation.
 */
export async function exportAuditAnchor(
  sequenceNumber: bigint,
  headHash: string,
  timestamp: Date
): Promise<void> {
  const anchorDir = path.dirname(config.anchorFile);
  if (!fs.existsSync(anchorDir)) {
    fs.mkdirSync(anchorDir, { recursive: true });
  }

  const anchorData: AuditAnchor = {
    sequenceNumber: sequenceNumber.toString(),
    headHash,
    timestamp: timestamp.toISOString(),
    exportedAt: new Date().toISOString()
  };

  const tempFile = `${config.anchorFile}.${Date.now()}.tmp`;
  await fs.promises.writeFile(tempFile, JSON.stringify(anchorData, null, 2), 'utf-8');
  await fs.promises.rename(tempFile, config.anchorFile);
}

/**
 * Reads the external anchor file if present
 */
export function loadAuditAnchor(): AuditAnchor | null {
  try {
    if (!fs.existsSync(config.anchorFile)) {
      return null;
    }
    const content = fs.readFileSync(config.anchorFile, 'utf-8');
    return JSON.parse(content) as AuditAnchor;
  } catch (error) {
    console.error('Failed to read audit anchor file:', error);
    return null;
  }
}
