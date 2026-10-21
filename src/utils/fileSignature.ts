import fs from 'fs';

export interface FileValidationResult {
  valid: boolean;
  detectedMime: string;
  error?: string;
}

/**
 * Validates the file buffer magic bytes against an extension whitelist.
 * Defense against Loophole L-15: Malicious Executables Disguised as Documents.
 */
export function validateFileBuffer(buffer: Buffer, originalFilename: string): FileValidationResult {
  if (!buffer || buffer.length === 0) {
    return { valid: false, detectedMime: 'unknown', error: 'File buffer is empty.' };
  }

  // 1. Critical Check: Immediately reject executables (Windows PE / Linux ELF)
  if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
    return { valid: false, detectedMime: 'application/x-dosexec', error: 'Disguised Windows executable (MZ header) detected.' };
  }
  if (buffer.length >= 4 && buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
    return { valid: false, detectedMime: 'application/x-elf', error: 'Disguised Linux ELF executable detected.' };
  }

  const ext = originalFilename.split('.').pop()?.toLowerCase();

  switch (ext) {
    case 'pdf': {
      // PDF must begin with %PDF- (0x25, 0x50, 0x44, 0x46, 0x2D)
      if (buffer.length >= 5 && buffer.toString('ascii', 0, 5) === '%PDF-') {
        return { valid: true, detectedMime: 'application/pdf' };
      }
      return { valid: false, detectedMime: 'unknown', error: 'File extension is .pdf but buffer lacks valid %PDF header.' };
    }

    case 'png': {
      // PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
      const pngHeader = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
      if (buffer.length >= 8 && pngHeader.every((b, i) => buffer[i] === b)) {
        return { valid: true, detectedMime: 'image/png' };
      }
      return { valid: false, detectedMime: 'unknown', error: 'File extension is .png but buffer lacks valid PNG header.' };
    }

    case 'jpg':
    case 'jpeg': {
      // JPEG magic bytes: FF D8 FF
      if (buffer.length >= 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
        return { valid: true, detectedMime: 'image/jpeg' };
      }
      return { valid: false, detectedMime: 'unknown', error: 'File extension is .jpg but buffer lacks valid JPEG header.' };
    }

    case 'txt': {
      // Full buffer validation: strictly valid UTF-8 and zero NUL bytes across all bytes
      try {
        const decoder = new TextDecoder('utf-8', { fatal: true });
        decoder.decode(buffer);
      } catch {
        return { valid: false, detectedMime: 'application/octet-stream', error: 'Plain text file contains invalid UTF-8 byte sequences.' };
      }
      for (let i = 0; i < buffer.length; i++) {
        if (buffer[i] === 0x00) {
          return { valid: false, detectedMime: 'application/octet-stream', error: 'Plain text file contains illegal null bytes.' };
        }
      }
      return { valid: true, detectedMime: 'text/plain' };
    }

    default:
      return {
        valid: false,
        detectedMime: 'unknown',
        error: `File extension .${ext} is not in the permitted whitelist (.pdf, .png, .jpg, .txt).`
      };
  }
}

/**
 * Validates a file from disk
 */
export async function validateDiskFile(filePath: string, originalFilename: string): Promise<FileValidationResult> {
  const buffer = await fs.promises.readFile(filePath);
  return validateFileBuffer(buffer, originalFilename);
}
