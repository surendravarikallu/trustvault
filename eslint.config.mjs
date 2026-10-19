import typescriptEslint from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';

export default [
  {
    files: ['src/**/*.ts'],
    ignores: ['src/dal/**/*.ts'],
    languageOptions: {
      parser: tsParser
    },
    plugins: {
      '@typescript-eslint': typescriptEslint
    },
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@prisma/client',
              message: 'Direct Prisma database imports are strictly prohibited outside src/dal/ and prisma/. All document queries must flow through src/dal/documentDal.ts.'
            }
          ],
          patterns: [
            {
              group: ['**/prisma*'],
              message: 'Direct database query access is restricted strictly to the Data Access Layer (src/dal/).'
            }
          ]
        }
      ]
    }
  }
];
