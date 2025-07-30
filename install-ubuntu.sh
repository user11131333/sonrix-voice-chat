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
    
    # Check if running from quick-start (auto-install mode)
    if [[ "$SONRIX_AUTO_INSTALL" == "yes" ]]; then
        print_status "Otomatik kurulum modu aktif"
        DOMAIN="$SONRIX_DOMAIN"
        EMAIL="$SONRIX_EMAIL"
        DB_ROOT_PASSWORD="$SONRIX_DB_ROOT_PASSWORD"
        DB_USER_PASSWORD="$SONRIX_DB_USER_PASSWORD"
        SSL_ENABLED="$SONRIX_SSL_ENABLED"
        INSTALL_NGINX="yes"
        INSTALL_PM2="yes"
        return
    fi
    
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
    sudo apt update -qq
    sudo apt upgrade -y -qq
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
    
    # MySQL root şifresini ayarla
    print_status "MySQL root şifresi ayarlanıyor..."
    sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$DB_ROOT_PASSWORD';"
    
    # MySQL güvenlik ayarları
    sudo mysql -u root -p$DB_ROOT_PASSWORD -e "DELETE FROM mysql.user WHERE User='';"
    sudo mysql -u root -p$DB_ROOT_PASSWORD -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    sudo mysql -u root -p$DB_ROOT_PASSWORD -e "DROP DATABASE IF EXISTS test;"
    sudo mysql -u root -p$DB_ROOT_PASSWORD -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';"
    sudo mysql -u root -p$DB_ROOT_PASSWORD -e "FLUSH PRIVILEGES;"
    
    print_status "MySQL 8.0 yüklendi ve yapılandırıldı"
}

setup_database() {
    print_status "Veritabanı oluşturuluyor..."
    
    # Basit database şemasını kullan
    if [[ -f "database-simple.sql" ]]; then
        mysql -u root -p$DB_ROOT_PASSWORD < database-simple.sql
    else
        print_error "database-simple.sql dosyası bulunamadı!"
        exit 1
    fi
    
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
    sudo sed -i "s/server_name _;/server_name $DOMAIN;/g" /etc/nginx/sites-available/sonrix-voice
    
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
    
    print_status "SSL kurulum script'i çalıştırılıyor..."
    
    # SSL setup script'ini çalıştır
    if [[ -f "ssl-setup.sh" ]]; then
        chmod +x ssl-setup.sh
        ./ssl-setup.sh "$DOMAIN" "$EMAIL"
    else
        print_warning "ssl-setup.sh bulunamadı, SSL manuel olarak kurulmalı"
    fi
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
    print_status "Ortam değişkenleri kontrol ediliyor..."
    
    # .env dosyası zaten mevcut mu kontrol et
    if [[ ! -f ".env" ]]; then
        print_status ".env dosyası oluşturuluyor..."
        
        # .env dosyası oluştur
        cp .env.example .env
        
        # Değişkenleri güncelle
        sed -i "s/your-domain.com/$DOMAIN/g" .env
        sed -i "s/your_secure_database_password/$DB_USER_PASSWORD/g" .env
        sed -i "s/your-email@gmail.com/$EMAIL/g" .env
        
        # JWT secret oluştur
        JWT_SECRET=$(openssl rand -base64 32)
        sed -i "s/your_very_long_and_secure_jwt_secret_key_here/$JWT_SECRET/g" .env
        
        # Session secret oluştur
        SESSION_SECRET=$(openssl rand -base64 32)
        sed -i "s/your_session_secret_key_here/$SESSION_SECRET/g" .env
    else
        print_status ".env dosyası zaten mevcut"
    fi
    
    # Dosya izinleri
    chmod 600 .env
    
    print_status "Ortam değişkenleri ayarlandı"
}

install_dependencies() {
    print_status "Uygulama bağımlılıkları yükleniyor..."
    
    npm install
    
    print_status "Bağımlılıklar yüklendi"
}

setup_systemd_service() {
    print_status "Systemd servisi oluşturuluyor..."
    
    # Systemd service dosyasını kopyala ve yapılandır
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
    
    # Log dizini oluştur
    mkdir -p logs
    
    # PM2 startup ayarla
    pm2 startup systemd -u $(whoami) --hp $(eval echo ~$(whoami)) | grep -E '^sudo' | bash
    
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
DB_USER="root"

# Yedekleme dizini oluştur
sudo mkdir -p $BACKUP_DIR

# .env dosyasından DB şifresini oku
DB_PASS=$(grep DB_PASSWORD .env | cut -d '=' -f2)

# Veritabanı yedeği
mysqldump -u $DB_USER -p$DB_PASS $DB_NAME > $BACKUP_DIR/db_backup_$DATE.sql

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
        if [ -f $(pwd)/logs/app.pid ]; then
            kill -USR1 \$(cat $(pwd)/logs/app.pid)
        fi
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
    
    # Uygulama başlamasını bekle
    sleep 5
    
    # Health check
    if curl -s http://localhost:3000/health | grep -q "healthy"; then
        print_status "Uygulama başarıyla başlatıldı"
    else
        print_warning "Uygulama başlatılamadı, logları kontrol edin"
    fi
}

print_summary() {
    echo -e "${GREEN}"
    echo "=================================="
    echo "  KURULUM BAŞARIYLA TAMAMLANDI!"
    echo "=================================="
    echo -e "${NC}"
    
    echo -e "${BLUE}Uygulama Bilgileri:${NC}"
    if [[ "$SSL_ENABLED" == "y" ]]; then
        echo "• URL: https://$DOMAIN"
        echo "• Admin Panel: https://$DOMAIN/admin"
    else
        echo "• URL: http://$DOMAIN"
        echo "• Admin Panel: http://$DOMAIN/admin"
    fi
    echo "• Local: http://localhost:3000"
    
    echo -e "${BLUE}Giriş Bilgileri:${NC}"
    echo "• Admin: admin / admin123"
    echo "• Demo: demo / demo123"
    
    echo -e "${BLUE}Veritabanı Bilgileri:${NC}"
    echo "• Host: localhost"
    echo "• Database: sonrix_voice"
    echo "• User: sonrix_user"
    
    echo -e "${BLUE}Servis Komutları:${NC}"
    if [[ "$INSTALL_PM2" == "y" ]]; then
        echo "• Başlat: pm2 start ecosystem.config.js"
        echo "• Durdur: pm2 stop sonrix-voice"
        echo "• Yeniden başlat: pm2 restart sonrix-voice"
        echo "• Loglar: pm2 logs sonrix-voice"
        echo "• Durum: pm2 status"
        echo "• Monitoring: pm2 monit"
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
    
    echo -e "${BLUE}Faydalı Komutlar:${NC}"
    echo "• Nginx test: sudo nginx -t"
    echo "• Nginx reload: sudo systemctl reload nginx"
    echo "• MySQL bağlan: mysql -u root -p"
    echo "• Firewall durum: sudo ufw status"
    
    if [[ "$SSL_ENABLED" == "y" ]]; then
        echo -e "${BLUE}SSL Bilgileri:${NC}"
        echo "• Sertifika: /etc/letsencrypt/live/$DOMAIN/"
        echo "• Yenileme: sudo certbot renew"
        echo "• Durum: sudo certbot certificates"
    fi
    
    echo -e "${YELLOW}Güvenlik Notları:${NC}"
    echo "• .env dosyasını git'e eklemeyin"
    echo "• Admin şifresini değiştirin"
    echo "• Düzenli yedekleme yapın"
    echo "• Güvenlik güncellemelerini takip edin"
    
    echo -e "${GREEN}✅ Sonrix Voice kullanmaya hazır!${NC}"
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
    setup_firewall
    setup_environment
    install_dependencies
    setup_systemd_service
    setup_pm2
    create_backup_script
    setup_monitoring
    start_application
    install_ssl  # SSL'i en son kur
    
    print_summary
}

# Script'i çalıştır
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
