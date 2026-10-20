module.exports = {
  apps: [
    {
      name: 'trustvault',
      script: 'dist/src/server.js',
      cwd: 'c:\\Users\\Admin\\Documents\\trustvault',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'production',
        PORT: 7777
      }
    }
  ]
};
