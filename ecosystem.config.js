module.exports = {
  apps: [{
    name: 'sonrix-voice',
    script: 'server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    // Logging
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true,
    
    // Memory and performance
    max_memory_restart: '1G',
    node_args: '--max-old-space-size=1024',
    
    // Restart settings
    watch: false,
    ignore_watch: ['node_modules', 'logs', '.git'],
    restart_delay: 4000,
    max_restarts: 10,
    min_uptime: '10s',
    
    // Health monitoring
    health_check_grace_period: 3000,
    health_check_timeout: 5000
  }],

  deploy: {
    production: {
      user: 'ubuntu',
      host: '45.147.46.196',
      ref: 'origin/main',
      repo: 'git@github.com:yourusername/sonrix-voice.git',
      path: '/var/www/sonrix-voice',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': ''
    }
  }
};
