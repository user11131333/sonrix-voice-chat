#!/bin/bash

# Sonrix Voice - Ubuntu 22.04 LTS Otomatik Kurulum Script'i
# MySQL 8.0 + Node.js 18+ + Nginx + PM2 + SSL

set -e

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logo
echo -e "${BLUE}"
echo "  ____              _      __   __    _          "
echo " / ___|  ___  _ __ (_)_  __\ \ / /__ (_) ___ ___ "
echo " \___ \ / _ \| '_ \| \ \/ / \ V / _ \| |/ __/ _ \\"
echo "  ___) | (_) | | | | |>  <   | | (_) | | (_|  __/"
echo " |____/ \___/|_| |_|_/_/\_\  |_|\___/|_|\___\___|"
echo "                                                 "
echo "        Ubuntu 22.04 LTS Kurulum Script'i       "
echo -e "${NC}"

# Değişkenler
DOMAIN=""
EMAIL=""
DB_ROOT_PASSWORD=""
DB_USER_PASSWORD=""
APP_SECRET=""
SSL_ENABLED="no"
INSTALL_NGINX="yes"
INSTALL_PM2="yes"

# Fonksiyonlar
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "Bu script'i root kullanıcısı ile çalıştırmayın!"
        exit 1
    fi
}

check_ubuntu() {
    if [[ ! -f /etc/lsb-release ]]; then
        print_error "Bu script sadece Ubuntu sistemler için tasarlanmıştır!"
        exit 1
    fi
    
    . /etc/lsb-release
    if [[ "$DISTRIB_ID" != "Ubuntu" ]]; then
        print_error "Bu script sadece Ubuntu sistemler için tasarlanmıştır!"
        exit 1
    fi
    
    if [[ "$DISTRIB_RELEASE" < "22.04" ]]; then
        print_error "Bu script Ubuntu 22.04 LTS veya daha yeni sürüm gerektirir!"
        exit 1
    fi
    
    print_status "Ubuntu $DISTRIB_RELEASE tespit edildi"
}

get_user_input() {
    echo -e "${BLUE}=== Kurulum Yapılandırması ===${NC}"
    
    read -p "Domain adı (örn: sonrix.example.com): " DOMAIN
    while [[ -z "$DOMAIN" ]]; do
        print_warning "Domain adı gerekli!"
        read -p "Domain adı: " DOMAIN
    done
    
    read -p "Email adresiniz (SSL sertifikası için): " EMAIL
    while [[ -z "$EMAIL" ]]; do
        print_warning "Email adresi gerekli!"
        read -p "Email adresiniz: " EMAIL
    done
    
    read -s -p "MySQL root şifresi: " DB_ROOT_PASSWORD
    echo
    while [[ ${#DB_ROOT_PASSWORD} -lt 8 ]]; do
        print_warning "Şifre en az 8 karakter olmalı!"
        read -s -p "MySQL root şifresi: " DB_ROOT_PASSWORD
        echo
    done
    
    read -s -p "Veritabanı kullanıcı şifresi: " DB_USER_PASSWORD
    echo
    while [[ ${#DB_USER_PASSWORD} -lt 8 ]]; do
        print_warning "Şifre en az 8 karakter olmalı!"
        read -s -p "Veritabanı kullanıcı şifresi: " DB_USER_PASSWORD
        echo
    done
    
    APP_SECRET=$(openssl rand -base64 32)
    
    read -p "SSL sertifikası yüklensin mi? (y/n) [y]: " SSL_INPUT
    SSL_ENABLED=${SSL_INPUT:-y}
    
    read -p "Nginx yüklensin mi? (y/n) [y]: " NGINX_INPUT
    INSTALL_NGINX=${NGINX_INPUT:-y}
    
    read -p "PM2 yüklensin mi? (y/n) [y]: " PM2_INPUT
    INSTALL_PM2=${PM2_INPUT:-y}
    
    echo -e "${GREEN}Yapılandırma tamamlandı!${NC}"
}

update_system() {
    print_status "Sistem güncelleniyor..."
    sudo apt update
    sudo apt upgrade -y
    sudo apt install -y curl wget git build-essential software-properties-common
}

install_nodejs() {
    print_status "Node.js 18 LTS yükleniyor..."
    
    # NodeSource repository ekle
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt install -y nodejs
    
    # Sürüm kontrolü
    NODE_VERSION=$(node --version)
    NPM_VERSION=$(npm --version)
    
    print_status "Node.js $NODE_VERSION ve npm $NPM_VERSION yüklendi"
    
    # Global paketler
    sudo npm install -g pm2 nodemon
}

install_mysql() {
    print_status "MySQL 8.0 yükleniyor..."
    
    # MySQL server yükle
    sudo apt install -y mysql-server mysql-client
    
    # MySQL güvenlik yapılandırması
    sudo mysql_secure_installation << EOF
y
$DB_ROOT_PASSWORD
$DB_ROOT_PASSWORD
y
y
y
y
EOF
    
    print_status "MySQL 8.0 yüklendi ve yapılandırıldı"
}

setup_database() {
    print_status "Veritabanı oluşturuluyor..."
    
    # Şifreyi SQL dosyasında değiştir
    sed -i "s/PLACEHOLDER_PASSWORD/$DB_USER_PASSWORD/g" ubuntu-mysql-setup.sql
    
    # SQL dosyasını çalıştır
    mysql -u root -p$DB_ROOT_PASSWORD < ubuntu-mysql-setup.sql
    
    print_status "Veritabanı başarıyla oluşturuldu"
}

install_nginx() {
    if [[ "$INSTALL_NGINX" != "y" ]]; then
        return
    fi
    
    print_status "Nginx yükleniyor..."
    
    sudo apt install -y nginx
    sudo systemctl enable nginx
    sudo systemctl start nginx
    
    # Nginx yapılandırması
    sudo cp nginx-sonrix.conf /etc/nginx/sites-available/sonrix-voice
    sudo sed -i "s/DOMAIN_NAME/$DOMAIN/g" /etc/nginx/sites-available/sonrix-voice
    
    # Site'i etkinleştir
    sudo ln -sf /etc/nginx/sites-available/sonrix-voice /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default
    
    # Nginx test et
    sudo nginx -t
    sudo systemctl reload nginx
    
    print_status "Nginx yüklendi ve yapılandırıldı"
}

install_ssl() {
    if [[ "$SSL_ENABLED" != "y" ]] || [[ "$INSTALL_NGINX" != "y" ]]; then
        return
    fi
    
    print_status "SSL sertifikası yükleniyor..."
    
    # Certbot yükle
    sudo snap install core; sudo snap refresh core
    sudo snap install --classic certbot
    sudo ln -sf /snap/bin/certbot /usr/bin/certbot
    
    # SSL sertifikası al
    sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $EMAIL
    
    # Otomatik yenileme
    sudo systemctl enable snap.certbot.renew.timer
    
    print_status "SSL sertifikası yüklendi"
}

setup_firewall() {
    print_status "Güvenlik duvarı yapılandırılıyor..."
    
    sudo ufw --force enable
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Gerekli portları aç
    sudo ufw allow ssh
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw allow 3000/tcp
    
    print_status "Güvenlik duvarı yapılandırıldı"
}

setup_environment() {
    print_status "Ortam değişkenleri ayarlanıyor..."
    
    # .env dosyası oluştur
    cat > .env << EOF
# Sunucu Ayarları
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# Veritabanı Ayarları
DB_HOST=localhost
DB_PORT=3306
DB_NAME=sonrix_voice
DB_USER=sonrix_user
DB_PASSWORD=$DB_USER_PASSWORD

# JWT Ayarları
JWT_SECRET=$APP_SECRET
JWT_EXPIRES_IN=24h

# Session Ayarları
SESSION_SECRET=$APP_SECRET
SESSION_TIMEOUT=1800000

# WebRTC Ayarları
STUN_SERVERS=stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302
TURN_SERVERS=

# Uygulama Ayarları
MAX_ROOM_USERS=20
MAX_ROOMS_PER_USER=3
CLEANUP_INTERVAL=300000
LOG_LEVEL=info

# SSL/TLS
SSL_ENABLED=$SSL_ENABLED
DOMAIN=$DOMAIN

# Admin Ayarları
ADMIN_EMAIL=$EMAIL
ENABLE_REGISTRATION=true
MAINTENANCE_MODE=false
EOF

    # Dosya izinleri
    chmod 600 .env
    
    print_status "Ortam değişkenleri ayarlandı"
}

install_dependencies() {
    print_status "Uygulama bağımlılıkları yükleniyor..."
    
    npm install
    npm audit fix
    
    print_status "Bağımlılıklar yüklendi"
}

setup_systemd_service() {
    print_status "Systemd servisi oluşturuluyor..."
    
    # Systemd service dosyasını kopyala
    sudo cp sonrix-voice.service /etc/systemd/system/
    sudo sed -i "s|WORKING_DIRECTORY|$(pwd)|g" /etc/systemd/system/sonrix-voice.service
    sudo sed -i "s|USER_NAME|$(whoami)|g" /etc/systemd/system/sonrix-voice.service
    
    # Servisi etkinleştir
    sudo systemctl daemon-reload
    sudo systemctl enable sonrix-voice
    
    print_status "Systemd servisi oluşturuldu"
}

setup_pm2() {
    if [[ "$INSTALL_PM2" != "y" ]]; then
        return
    fi
    
    print_status "PM2 yapılandırılıyor..."
    
    # PM2 ecosystem dosyası oluştur
    cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'sonrix-voice',
    script: 'server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: 'logs/err.log',
    out_file: 'logs/out.log',
    log_file: 'logs/combined.log',
    time: true,
    max_memory_restart: '1G',
    node_args: '--max-old-space-size=1024',
    watch: false,
    ignore_watch: ['node_modules', 'logs'],
    restart_delay: 4000,
    max_restarts: 10,
    min_uptime: '10s'
  }]
};
EOF
    
    # Log dizini oluştur
    mkdir -p logs
    
    # PM2 startup
    pm2 startup systemd -u $(whoami) --hp $(eval echo ~$(whoami))
    
    print_status "PM2 yapılandırıldı"
}

create_backup_script() {
    print_status "Yedekleme script'i oluşturuluyor..."
    
    cat > backup.sh << 'EOF'
#!/bin/bash

# Sonrix Voice Yedekleme Script'i

BACKUP_DIR="/var/backups/sonrix-voice"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="sonrix_voice"
DB_USER="sonrix_user"

# Yedekleme dizini oluştur
sudo mkdir -p $BACKUP_DIR

# Veritabanı yedeği
mysqldump -u $DB_USER -p $DB_NAME > $BACKUP_DIR/db_backup_$DATE.sql

# Uygulama dosyaları yedeği
tar -czf $BACKUP_DIR/app_backup_$DATE.tar.gz . --exclude=node_modules --exclude=logs --exclude=*.log

# Eski yedekleri temizle (30 günden eski)
find $BACKUP_DIR -name "*.sql" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Yedekleme tamamlandı: $BACKUP_DIR"
EOF
    
    chmod +x backup.sh
    
    # Crontab'a ekle (günlük yedekleme)
    (crontab -l 2>/dev/null; echo "0 2 * * * $(pwd)/backup.sh") | crontab -
    
    print_status "Yedekleme script'i oluşturuldu"
}

setup_monitoring() {
    print_status "İzleme yapılandırılıyor..."
    
    # Log rotasyon
    sudo tee /etc/logrotate.d/sonrix-voice << EOF > /dev/null
$(pwd)/logs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 $(whoami) $(whoami)
    postrotate
        pm2 reload sonrix-voice
    endscript
}
EOF
    
    print_status "İzleme yapılandırıldı"
}

start_application() {
    print_status "Uygulama başlatılıyor..."
    
    if [[ "$INSTALL_PM2" == "y" ]]; then
        # PM2 ile başlat
        pm2 start ecosystem.config.js
        pm2 save
    else
        # Systemd ile başlat
        sudo systemctl start sonrix-voice
    fi
    
    print_status "Uygulama başlatıldı"
}

print_summary() {
    echo -e "${GREEN}"
    echo "=================================="
    echo "  KURULUM BAŞARIYLA TAMAMLANDI!"
    echo "=================================="
    echo -e "${NC}"
    
    echo -e "${BLUE}Uygulama Bilgileri:${NC}"
    echo "• URL: https://$DOMAIN"
    echo "• Local: http://localhost:3000"
    echo "• Admin Panel: https://$DOMAIN/admin.html"
    
    echo -e "${BLUE}Veritabanı Bilgileri:${NC}"
    echo "• Host: localhost"
    echo "• Database: sonrix_voice"
    echo "• User: sonrix_user"
    
    echo -e "${BLUE}Servis Komutları:${NC}"
    if [[ "$INSTALL_PM2" == "y" ]]; then
        echo "• Başlat: pm2 start sonrix-voice"
        echo "• Durdur: pm2 stop sonrix-voice"
        echo "• Yeniden başlat: pm2 restart sonrix-voice"
        echo "• Loglar: pm2 logs sonrix-voice"
        echo "• Durum: pm2 status"
    else
        echo "• Başlat: sudo systemctl start sonrix-voice"
        echo "• Durdur: sudo systemctl stop sonrix-voice"
        echo "• Yeniden başlat: sudo systemctl restart sonrix-voice"
        echo "• Durum: sudo systemctl status sonrix-voice"
        echo "• Loglar: sudo journalctl -u sonrix-voice -f"
    fi
    
    echo -e "${BLUE}Yedekleme:${NC}"
    echo "• Manuel: ./backup.sh"
    echo "• Otomatik: Her gün saat 02:00"
    
    echo -e "${BLUE}Yapılandırma Dosyaları:${NC}"
    echo "• Uygulama: .env"
    echo "• Nginx: /etc/nginx/sites-available/sonrix-voice"
    echo "• PM2: ecosystem.config.js"
    
    echo -e "${YELLOW}İlk admin kullanıcısını oluşturmak için:${NC}"
    echo "• https://$DOMAIN/login.html adresine gidin"
    echo "• 'Kayıt Ol' sekmesinden admin hesabı oluşturun"
    
    echo -e "${GREEN}Kurulum tamamlandı! Sonrix Voice kullanmaya hazır.${NC}"
}

# Ana fonksiyon
main() {
    echo -e "${BLUE}Sonrix Voice Kurulum Script'i başlatılıyor...${NC}"
    
    check_root
    check_ubuntu
    get_user_input
    
    echo -e "${YELLOW}Kurulum başlıyor... Bu işlem birkaç dakika sürebilir.${NC}"
    
    update_system
    install_nodejs
    install_mysql
    setup_database
    install_nginx
    install_ssl
    setup_firewall
    setup_environment
    install_dependencies
    setup_systemd_service
    setup_pm2
    create_backup_script
    setup_monitoring
    start_application
    
    print_summary
}

# Script'i çalıştır
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
