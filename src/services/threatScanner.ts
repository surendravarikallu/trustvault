import fs from 'fs';

export interface ThreatScanResult {
  isSafe: boolean;
  threatType?: string;
  details?: string;
}

export class ThreatScanner {
  /**
   * Scans a file on disk for embedded malware, weaponized macro binaries,
   * active scripting streams, or PDF exploit payloads.
   */
  public static async scanFile(filePath: string, originalFilename: string): Promise<ThreatScanResult> {
    const buffer = await fs.promises.readFile(filePath);
    const ext = originalFilename.slice(originalFilename.lastIndexOf('.')).toLowerCase();

    // 1. PDF Deep Exploit Stream Inspection
    if (ext === '.pdf') {
      const pdfString = buffer.toString('binary');

      if (pdfString.includes('/Launch')) {
        return {
          isSafe: false,
          threatType: 'PDF_EXPLOIT_LAUNCH_COMMAND',
          details: 'PDF contains weaponized /Launch action capable of executing OS commands.'
        };
      }

      if (pdfString.includes('/JavaScript') || pdfString.includes('/JS')) {
        return {
          isSafe: false,
          threatType: 'PDF_EMBEDDED_JAVASCRIPT',
          details: 'PDF contains active /JavaScript or /JS executable stream.'
        };
      }

      if (pdfString.includes('/EmbeddedFiles') && pdfString.includes('/OpenAction')) {
        return {
          isSafe: false,
          threatType: 'PDF_AUTO_EXEC_PAYLOAD',
          details: 'PDF contains embedded binary files configured for automatic execution (/OpenAction).'
        };
      }
    }

    // 2. OOXML / Office Macro Inspection (.docx, .xlsx, .pptx)
    if (['.docx', '.xlsx', '.pptx'].includes(ext)) {
      const ooxmlString = buffer.toString('binary');

      // Check for embedded VBA Macro Project
      if (ooxmlString.includes('vbaProject.bin') || ooxmlString.includes('word/vbaProject.bin')) {
        return {
          isSafe: false,
          threatType: 'OFFICE_WEAPONIZED_MACRO',
          details: 'Office document contains embedded Visual Basic for Applications (vbaProject.bin) macro code.'
        };
      }

      // Check for external template injection / OLE object exploits
      if (ooxmlString.includes('oleObject') && ooxmlString.includes('TargetMode="External"')) {
        return {
          isSafe: false,
          threatType: 'OFFICE_EXTERNAL_OLE_INJECTION',
          details: 'Office document contains external OLE object / remote template injection payload.'
        };
      }
    }

    // 3. Plaintext and Script Payload Heuristics
    if (['.txt', '.csv', '.json', '.xml'].includes(ext)) {
      const textSample = buffer.subarray(0, 4096).toString('utf8');

      if (/powershell\s+(-enc|-encodedcommand|-e\s)/i.test(textSample)) {
        return {
          isSafe: false,
          threatType: 'OBFUSCATED_POWERSHELL_PAYLOAD',
          details: 'File contains obfuscated PowerShell command invocation.'
        };
      }

      if (/^(#!(\/usr)?\/bin\/(bash|sh|zsh|python|perl)|<\?php)/i.test(textSample.trim())) {
        return {
          isSafe: false,
          threatType: 'EMBEDDED_SHELL_SCRIPT',
          details: 'Text document contains executable shell shebang or server-side script header.'
        };
      }
    }

    return { isSafe: true };
  }
}
