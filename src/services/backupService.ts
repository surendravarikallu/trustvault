import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { config } from '../config';
import { logAuditEvent } from './auditService';
import { exportDatabaseSnapshot } from '../dal/backupDal';
import { AuditStatus } from '../dal/types';

const BACKUP_DIR = path.resolve(process.cwd(), 'storage/backups');

export interface BackupManifest {
  backupId: string;
  createdAt: string;
  environment: string;
  databaseStats: {
    users: number;
    documents: number;
    versions: number;
    permissions: number;
    auditLogs: number;
  };
  auditHead: {
    sequenceNumber: string;
    headHash: string;
  };
  storageFilesCount: number;
  manifestHmac: string;
}

export class BackupService {
  private static ensureBackupDir(): void {
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true });
    }
  }

  /**
   * Generates a full, cryptographically verified backup archive.
   */
  public static async createFullBackup(operatorEmail = 'system@trustvault.local'): Promise<{
    backupId: string;
    backupPath: string;
    manifest: BackupManifest;
  }> {
    this.ensureBackupDir();

    const backupId = crypto.randomUUID();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFolder = path.join(BACKUP_DIR, `backup_${timestamp}_${backupId.slice(0, 8)}`);
    fs.mkdirSync(backupFolder, { recursive: true });

    // 1. Export Database Tables via DAL
    const dbDump = await exportDatabaseSnapshot();

    const dbDumpPath = path.join(backupFolder, 'database_dump.json');
    await fs.promises.writeFile(
      dbDumpPath,
      JSON.stringify(dbDump, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2),
      'utf-8'
    );

    // 2. Snapshot Storage Blobs
    const storageBackupDir = path.join(backupFolder, 'storage_blobs');
    fs.mkdirSync(storageBackupDir, { recursive: true });

    let storageFilesCount = 0;
    if (fs.existsSync(config.storageDir)) {
      const files = await fs.promises.readdir(config.storageDir);
      for (const file of files) {
        const srcPath = path.join(config.storageDir, file);
        const stat = await fs.promises.stat(srcPath);
        if (stat.isFile()) {
          await fs.promises.copyFile(srcPath, path.join(storageBackupDir, file));
          storageFilesCount++;
        }
      }
    }

    // 3. Snapshot External Audit Anchor
    if (fs.existsSync(config.anchorFile)) {
      await fs.promises.copyFile(config.anchorFile, path.join(backupFolder, 'audit_anchor.json'));
    }

    // 4. Calculate Audit Head
    const latestAudit = dbDump.auditLogs[dbDump.auditLogs.length - 1];
    const auditHead = {
      sequenceNumber: latestAudit ? latestAudit.sequenceNumber.toString() : '0',
      headHash: latestAudit ? latestAudit.hash : 'GENESIS'
    };

    // 5. Generate HMAC-Signed Manifest
    const manifestData = {
      backupId,
      createdAt: new Date().toISOString(),
      environment: config.nodeEnv,
      databaseStats: {
        users: dbDump.users.length,
        documents: dbDump.documents.length,
        versions: dbDump.versions.length,
        permissions: dbDump.permissions.length,
        auditLogs: dbDump.auditLogs.length
      },
      auditHead,
      storageFilesCount
    };

    const manifestHmac = crypto
      .createHmac('sha256', config.auditHmacSecret)
      .update(JSON.stringify(manifestData, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)))
      .digest('hex');

    const manifest: BackupManifest = {
      ...manifestData,
      manifestHmac
    };

    await fs.promises.writeFile(
      path.join(backupFolder, 'manifest.json'),
      JSON.stringify(manifest, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2),
      'utf-8'
    );

    // 6. Record Audit Event
    await logAuditEvent({
      action: 'SYSTEM_BACKUP_CREATED',
      userEmail: operatorEmail,
      status: AuditStatus.SUCCESS,
      ipAddress: '127.0.0.1',
      userAgent: 'BackupService Daemon',
      details: `Full backup created: ID ${backupId}, ${dbDump.auditLogs.length} audit entries, ${storageFilesCount} storage blobs.`
    });

    // 7. Prune Older Backups (Retain last 7)
    await this.pruneOldBackups(7);

    return {
      backupId,
      backupPath: backupFolder,
      manifest
    };
  }

  /**
   * Resolves a backup identifier or folder path to the absolute directory path.
   */
  public static async resolveBackupPath(backupPathOrId: string): Promise<string | null> {
    if (fs.existsSync(backupPathOrId)) {
      return backupPathOrId;
    }
    this.ensureBackupDir();
    const entries = await fs.promises.readdir(BACKUP_DIR);
    for (const entry of entries) {
      const fullPath = path.join(BACKUP_DIR, entry);
      const manifestPath = path.join(fullPath, 'manifest.json');
      if (fs.existsSync(manifestPath)) {
        try {
          const raw = await fs.promises.readFile(manifestPath, 'utf-8');
          const m = JSON.parse(raw);
          if (m.backupId === backupPathOrId || entry.includes(backupPathOrId)) {
            return fullPath;
          }
        } catch {
          // ignore corrupted
        }
      }
    }
    return null;
  }

  /**
   * Verifies the cryptographic integrity of a backup archive folder.
   */
  public static async verifyBackupArchive(backupPathOrId: string): Promise<{
    isValid: boolean;
    manifest: BackupManifest;
    errors: string[];
  }> {
    const backupPath = (await this.resolveBackupPath(backupPathOrId)) || backupPathOrId;
    const errors: string[] = [];
    const manifestPath = path.join(backupPath, 'manifest.json');

    if (!fs.existsSync(manifestPath)) {
      return { isValid: false, manifest: null as any, errors: ['Manifest file missing from backup.'] };
    }

    const manifestRaw = await fs.promises.readFile(manifestPath, 'utf-8');
    const manifest: BackupManifest = JSON.parse(manifestRaw);

    // Verify HMAC of the manifest itself
    const { manifestHmac, ...unsignedData } = manifest;
    const computedHmac = crypto
      .createHmac('sha256', config.auditHmacSecret)
      .update(JSON.stringify(unsignedData, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)))
      .digest('hex');

    if (manifestHmac !== computedHmac) {
      errors.push('Manifest HMAC signature mismatch! Backup metadata has been tampered with.');
    }

    // Verify database dump existence and parseability
    const dbDumpPath = path.join(backupPath, 'database_dump.json');
    if (!fs.existsSync(dbDumpPath)) {
      errors.push('Database dump missing from backup folder.');
    } else {
      const dumpRaw = await fs.promises.readFile(dbDumpPath, 'utf-8');
      const dump = JSON.parse(dumpRaw);
      if (dump.auditLogs.length !== manifest.databaseStats.auditLogs) {
        errors.push(`Audit log count mismatch: expected ${manifest.databaseStats.auditLogs}, found ${dump.auditLogs.length}`);
      }
    }

    return {
      isValid: errors.length === 0,
      manifest,
      errors
    };
  }

  /**
   * Lists available backup archives with their metadata
   */
  public static async listBackups(): Promise<BackupManifest[]> {
    this.ensureBackupDir();
    const entries = await fs.promises.readdir(BACKUP_DIR);
    const manifests: BackupManifest[] = [];

    for (const entry of entries) {
      const fullPath = path.join(BACKUP_DIR, entry);
      const manifestPath = path.join(fullPath, 'manifest.json');
      if (fs.existsSync(manifestPath)) {
        try {
          const raw = await fs.promises.readFile(manifestPath, 'utf-8');
          manifests.push(JSON.parse(raw));
        } catch {
          // Skip corrupted entries
        }
      }
    }

    return manifests.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  /**
   * Prunes backup directories, retaining the newest N copies.
   */
  public static async pruneOldBackups(retainCount = 7): Promise<number> {
    this.ensureBackupDir();
    const entries = await fs.promises.readdir(BACKUP_DIR);
    const validFolders: { name: string; mtime: number }[] = [];

    for (const entry of entries) {
      const fullPath = path.join(BACKUP_DIR, entry);
      const stat = await fs.promises.stat(fullPath);
      if (stat.isDirectory()) {
        validFolders.push({ name: fullPath, mtime: stat.mtimeMs });
      }
    }

    validFolders.sort((a, b) => b.mtime - a.mtime);

    let pruned = 0;
    if (validFolders.length > retainCount) {
      const toDelete = validFolders.slice(retainCount);
      for (const folder of toDelete) {
        await fs.promises.rm(folder.name, { recursive: true, force: true });
        pruned++;
      }
    }

    return pruned;
  }
}
