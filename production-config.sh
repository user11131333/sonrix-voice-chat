#!/bin/bash

# Sonrix Voice - Production Configuration
# sonrix.tech sunucusu için hazır konfigürasyon

# ======================
# SUNUCU BİLGİLERİ
# ======================
SERVER_IP="45.147.46.196"               # Sunucu IP adresi
DOMAIN="sonrix.tech"                     # Domain adı
SSH_PORT="22"                            # SSH port
TIMEZONE="Europe/Istanbul"               # Sunucu saat dilimi

# ======================
# VERİTABANI BİLGİLERİ
# ======================
DB_ROOT_PASSWORD="Sonrix2024_MySQL_Root!"       # MySQL root şifresi
DB_USER_PASSWORD="Sonrix2024_App_DB_Pass!"      # Uygulama veritabanı şifresi
DB_NAME="sonrix_voice"                           # Veritabanı adı
DB_USER="sonrix_user"                            # Veritabanı kullanıcısı

# ======================
# UYGULAMA BİLGİLERİ  
# ======================
APP_PORT="3000"                          # Uygulama portu
JWT_SECRET="sonrix-super-secure-jwt-secret-key-2024-production-ready"   # JWT secret (32+ karakter)
SESSION_SECRET="sonrix-session-secret-key-different-from-jwt-2024"      # Session secret (32+ karakter)

# ======================
# ADMIN BİLGİLERİ
# ======================
ADMIN_USERNAME="admin"                   # Admin kullanıcı adı
ADMIN_EMAIL="admin@sonrix.tech"          # Admin email adresi
ADMIN_PASSWORD="SonrixAdmin2024!"        # Admin şifresi

# ======================
# SSL/HTTPS BİLGİLERİ
# ======================
ENABLE_SSL="yes"                         # SSL sertifikası kur
LETSENCRYPT_EMAIL="admin@sonrix.tech"    # Let's Encrypt email
FORCE_HTTPS="yes"                        # HTTP'yi HTTPS'e yönlendir

# ======================
# GÜVENLİK AYARLARI
# ======================
FIREWALL_ENABLED="yes"                   # UFW firewall etkinleştir
SSH_KEY_ONLY="no"                        # Şimdilik password ile giriş aktif
FAIL2BAN_ENABLED="yes"                   # Fail2ban kur (brute force koruması)

# ======================
# PERFORMANS AYARLARI
# ======================
PM2_INSTANCES="max"                      # PM2 instance sayısı (CPU core sayısı kadar)
NGINX_WORKER_PROCESSES="auto"            # Nginx worker sayısı
MYSQL_INNODB_BUFFER_SIZE="512M"          # MySQL InnoDB buffer boyutu (RAM'e göre ayarlandı)

# ======================
# MONITORING AYARLARI
# ======================
ENABLE_MONITORING="yes"                  # Sistem izleme etkinleştir
LOG_LEVEL="info"                         # Log seviyesi
BACKUP_ENABLED="yes"                     # Otomatik yedekleme etkinleştir
BACKUP_RETENTION_DAYS="30"               # Yedek saklama süresi

# ======================
# WEBHOOK/BİLDİRİM AYARLARI
# ======================
SLACK_WEBHOOK=""                         # Slack webhook URL (opsiyonel)
DISCORD_WEBHOOK=""                       # Discord webhook URL (opsiyonel)
EMAIL_NOTIFICATIONS="yes"                # Email bildirimleri

# ======================
# UYGULAMA AYARLARI
# ======================
MAX_ROOM_USERS="20"                      # Odada maksimum kullanıcı sayısı
MAX_ROOMS_PER_USER="5"                   # Kullanıcı başına max oda sayısı
ROOM_TIMEOUT_MINUTES="60"                # Oda otomatik kapatma (dakika)
RATE_LIMIT_ENABLED="yes"                 # Rate limiting etkinleştir
MAINTENANCE_MODE="no"                    # Bakım modu kapalı

# ======================
# VALIDATION FUNCTION
# ======================
validate_config() {
    local errors=0
    
    echo "🔍 Konfigürasyon doğrulanıyor..."
    
    # IP format kontrolü
    if [[ ! "$SERVER_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "❌ SERVER_IP geçersiz format"
        errors=$((errors + 1))
    fi
    
    # Domain kontrolü
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "❌ DOMAIN geçersiz format"
        errors=$((errors + 1))
    fi
    
    # Email kontrolü
    if [[ ! "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "❌ ADMIN_EMAIL geçersiz format"
        errors=$((errors + 1))
    fi
    
    # Şifre uzunluk kontrolü
    if [[ ${#DB_ROOT_PASSWORD} -lt 8 ]]; then
        echo "❌ DB_ROOT_PASSWORD en az 8 karakter olmalı"
        errors=$((errors + 1))
    fi
    
    if [[ ${#JWT_SECRET} -lt 32 ]]; then
        echo "❌ JWT_SECRET en az 32 karakter olmalı"
        errors=$((errors + 1))
    fi
    
    if [[ $errors -eq 0 ]]; then
        echo "✅ Konfigürasyon geçerli"
        return 0
    else
        echo "❌ $errors hata bulundu"
        return 1
    fi
}

# ======================
# GENERATE SECRETS FUNCTION
# ======================
generate_secrets() {
    echo "🔐 Güvenlik anahtarları hazırlanıyor..."
    
    # Şifreler zaten ayarlandı, sadece bilgi ver
    echo "✅ JWT_SECRET hazır"
    echo "✅ SESSION_SECRET hazır"
    echo "✅ ADMIN_PASSWORD hazır: $ADMIN_PASSWORD"
    echo "⚠️  Admin şifrenizi kaydedin: $ADMIN_PASSWORD"
}

# ======================
# EXPORT ENV FUNCTION
# ======================
export_env() {
    cat > .env << EOF
# Sonrix Voice - Production Environment
# sonrix.tech sunucusu - Generated on $(date)

# Server Configuration
NODE_ENV=production
PORT=$APP_PORT
HOST=0.0.0.0
DOMAIN=$DOMAIN
SSL_ENABLED=true
SERVER_IP=$SERVER_IP

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_USER_PASSWORD
DB_CONNECTION_LIMIT=20
DB_TIMEOUT=60000

# Security Configuration
JWT_SECRET=$JWT_SECRET
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d
SESSION_SECRET=$SESSION_SECRET
SESSION_TIMEOUT=1800000
BCRYPT_ROUNDS=12

# Application Settings
APP_NAME=Sonrix Voice
APP_VERSION=2.0.0
MAX_ROOM_USERS=$MAX_ROOM_USERS
MAX_ROOMS_PER_USER=$MAX_ROOMS_PER_USER
ROOM_TIMEOUT_MINUTES=$ROOM_TIMEOUT_MINUTES
CLEANUP_INTERVAL_MINUTES=5
ENABLE_REGISTRATION=true
MIN_PASSWORD_LENGTH=8
MAX_USERNAME_LENGTH=50

# Admin Configuration
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_SESSION_TIMEOUT=3600000

# WebRTC Configuration
STUN_SERVERS=stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302,stun:stun2.l.google.com:19302

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
LOGIN_RATE_LIMIT_ATTEMPTS=5
LOGIN_RATE_LIMIT_WINDOW_MS=300000

# Logging Configuration
LOG_LEVEL=$LOG_LEVEL
LOG_FILE_PATH=./logs/app.log
LOG_MAX_FILE_SIZE=10m
LOG_MAX_FILES=5
ENABLE_CONSOLE_LOG=true
ENABLE_FILE_LOG=true

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
EMAIL_FROM=noreply@$DOMAIN
EMAIL_FROM_NAME=Sonrix Voice

# Security Headers
HELMET_ENABLED=true
TRUST_PROXY=true
MAX_REQUEST_SIZE=10mb
ENABLE_CSRF_PROTECTION=true
COOKIE_SECURE=true
COOKIE_HTTP_ONLY=true
COOKIE_SAME_SITE=strict

# CORS Configuration
CORS_ORIGIN=https://$DOMAIN
CORS_CREDENTIALS=true
CORS_METHODS=GET,HEAD,PUT,PATCH,POST,DELETE

# Monitoring & Health
ENABLE_METRICS=true
METRICS_PORT=9090
HEALTH_CHECK_ENDPOINT=/health
ENABLE_PERFORMANCE_MONITORING=true

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_SCHEDULE=0 2 * * *
BACKUP_RETENTION_DAYS=$BACKUP_RETENTION_DAYS
BACKUP_PATH=/var/backups/sonrix-voice

# Maintenance
MAINTENANCE_MODE=false
MAINTENANCE_MESSAGE=Sistem bakımda. Lütfen daha sonra tekrar deneyin.

# WebSocket Configuration
WEBSOCKET_PING_TIMEOUT=5000
WEBSOCKET_PING_INTERVAL=25000
WEBSOCKET_TRANSPORTS=websocket,polling

# Performance Settings
CLUSTER_ENABLED=true
CLUSTER_WORKERS=0
KEEP_ALIVE_TIMEOUT=65000
MAX_CONNECTIONS=1000

# Debug (Production'da false)
DEBUG_ENABLED=false
ENABLE_REQUEST_LOGGING=true
ENABLE_ERROR_STACK_TRACE=false
EOF
    
    chmod 600 .env
    echo "✅ .env dosyası oluşturuldu (izinler 600 olarak ayarlandı)"
}

# ======================
# MAIN FUNCTION
# ======================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "🚀 Sonrix Voice Production Configuration - sonrix.tech"
    echo ""
    echo "Mevcut ayarlar:"
    echo "- Server IP: $SERVER_IP"
    echo "- Domain: $DOMAIN"
    echo "- SSL: $ENABLE_SSL"
    echo "- Admin Email: $ADMIN_EMAIL"
    echo "- Admin Password: $ADMIN_PASSWORD"
    echo ""
    
    if validate_config; then
        read -p "Konfigürasyonu kullanarak .env dosyası oluşturayım mı? (y/n) [y]: " create_env
        create_env=${create_env:-y}
        
        if [[ "$create_env" == "y" || "$create_env" == "Y" ]]; then
            generate_secrets
            export_env
            echo ""
            echo "✅ Hazır! Şimdi kurulumu başlatabilirsiniz:"
            echo ""
            echo "   # Tek komutla kurulum:"
            echo "   ./quick-start.sh"
            echo ""
            echo "   # Veya manuel kurulum:"
            echo "   ./install-ubuntu.sh"
            echo ""
            echo "🔐 ÖNEMLİ: Admin bilgilerinizi kaydedin:"
            echo "   Kullanıcı: $ADMIN_USERNAME"
            echo "   Şifre: $ADMIN_PASSWORD"  
            echo "   Email: $ADMIN_EMAIL"
        fi
    fi
fi
