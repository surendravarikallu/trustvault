import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  jwtSecret: process.env.JWT_SECRET || 'trustvault_fallback_secret_key_2026',
  jwtExpiresIn: '8h',
  uploadDir: path.resolve(process.cwd(), process.env.UPLOAD_DIR || 'storage/uploads'),
  maxFileSize: 25 * 1024 * 1024, // 25 MB
  allowedMimeTypes: [
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // .docx
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
    'text/plain',
    'text/csv',
    'image/png',
    'image/jpeg'
  ],
  allowedExtensions: ['.pdf', '.docx', '.xlsx', '.txt', '.csv', '.png', '.jpg', '.jpeg']
};
