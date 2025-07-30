{
  "name": "sonrix-voice",
  "version": "2.0.0",
  "description": "WebRTC sesli sohbet uygulaması - Ubuntu 22.04 + MySQL 8.0 optimized",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "install-deps": "npm install && npm audit fix",
    "setup-db": "mysql -u root -p < ubuntu-mysql-setup.sql",
    "test": "npm run test:unit && npm run test:integration",
    "test:unit": "jest --testPathPattern=tests/unit",
    "test:integration": "jest --testPathPattern=tests/integration",
    "lint": "eslint . --ext .js",
    "lint:fix": "eslint . --ext .js --fix",
    "security-check": "npm audit && snyk test",
    "build": "npm run lint && npm run test",
    "deploy": "pm2 start ecosystem.config.js",
    "logs": "pm2 logs sonrix-voice",
    "restart": "pm2 restart sonrix-voice",
    "stop": "pm2 stop sonrix-voice",
    "monitor": "pm2 monit",
    "backup-db": "mysqldump -u sonrix_user -p sonrix_voice > backup_$(date +%Y%m%d_%H%M%S).sql",
    "restore-db": "mysql -u sonrix_user -p sonrix_voice < $BACKUP_FILE"
  },
  "keywords": [
    "webrtc",
    "voice-chat",
    "real-time",
    "nodejs",
    "socket.io",
    "mysql",
    "ubuntu"
  ],
  "author": {
    "name": "Sonrix Voice Team",
    "email": "info@sonrixvoice.com"
  },
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/yourusername/sonrix-voice.git"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=8.0.0"
  },
  "dependencies": {
    "express": "^4.18.2",
    "socket.io": "^4.7.4",
    "mysql2": "^3.6.5",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "compression": "^1.7.4",
    "express-rate-limit": "^7.1.5",
    "express-validator": "^7.0.1",
    "dotenv": "^16.3.1",
    "winston": "^3.11.0",
    "winston-daily-rotate-file": "^4.7.1",
    "joi": "^17.11.0",
    "uuid": "^9.0.1",
    "moment": "^2.29.4",
    "lodash": "^4.17.21",
    "crypto": "^1.0.1",
    "node-cron": "^3.0.3",
    "pm2": "^5.3.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "eslint": "^8.55.0",
    "eslint-config-standard": "^17.1.0",
    "eslint-plugin-node": "^11.1.0",
    "eslint-plugin-promise": "^6.1.1",
    "prettier": "^3.1.0",
    "husky": "^8.0.3",
    "lint-staged": "^15.2.0",
    "snyk": "^1.1260.0",
    "@types/node": "^20.10.4"
  },
  "optionalDependencies": {
    "bufferutil": "^4.0.8",
    "utf-8-validate": "^6.0.3"
  },
  "peerDependencies": {
    "redis": "^4.6.10",
    "ioredis": "^5.3.2"
  },
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged",
      "pre-push": "npm run test"
    }
  },
  "lint-staged": {
    "*.js": [
      "eslint --fix",
      "prettier --write",
      "git add"
    ]
  },
  "jest": {
    "testEnvironment": "node",
    "coverageDirectory": "coverage",
    "collectCoverageFrom": [
      "**/*.js",
      "!node_modules/**",
      "!coverage/**",
      "!tests/**"
    ],
    "testMatch": [
      "**/tests/**/*.test.js"
    ]
  },
  "eslintConfig": {
    "extends": ["standard"],
    "env": {
      "node": true,
      "es6": true,
      "jest": true
    },
    "rules": {
      "no-console": "warn",
      "indent": ["error", 2],
      "quotes": ["error", "single"],
      "semi": ["error", "always"]
    }
  },
  "config": {
    "mysql_host": "localhost",
    "mysql_port": 3306,
    "mysql_database": "sonrix_voice",
    "mysql_user": "sonrix_user",
    "server_port": 3000,
    "max_room_users": 20,
    "max_rooms_per_user": 3,
    "session_timeout": 1800000,
    "cleanup_interval": 300000
  },
  "os": [
    "linux"
  ],
  "cpu": [
    "x64",
    "arm64"
  ],
  "funding": {
    "type": "github",
    "url": "https://github.com/sponsors/yourusername"
  },
  "bugs": {
    "url": "https://github.com/yourusername/sonrix-voice/issues"
  },
  "homepage": "https://github.com/yourusername/sonrix-voice#readme",
  "private": false,
  "preferGlobal": false,
  "publishConfig": {
    "registry": "https://registry.npmjs.org/"
  }
}
