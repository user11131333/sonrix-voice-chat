#!/bin/bash

# Sonrix Voice - Quick Start Script
# Ubuntu 22.04 için tek komutla kurulum

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logo
echo -e "${BLUE}"
cat << 'EOF'
  ____              _      __   __    _          
 / ___|  ___  _ __ (_)_  __\ \ / /__ (_) ___ ___ 
 \___ \ / _ \| '_ \| \ \/ / \ V / _ \| |/ __/ _ \
  ___) | (_) | | | | |>  <   | | (_) | | (_|  __/
 |____/ \___/|_| |_|_/_/\_\  |_|\___/|_|\___\___|
                                                 
        🚀 Quick Start - sonrix.tech
EOF
echo -e "${NC}"

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Root kontrol
if [[ $EUID -eq 0 ]]; then
    print_error "Bu script'i root kullanıcısı ile çalıştırmayın!"
    exit 1
fi

# Ubuntu kontrol
if [[ ! -f /etc/lsb-release ]]; then
    print_error "Bu script sadece Ubuntu sistemler için!"
    exit 1
fi

print_status "Sonrix Voice Quick Start başlatılıyor..."

# Gerekli dosyaları kontrol et
required_files=(
    "production-config.sh"
    "install-ubuntu.sh"
    "ubuntu-mysql-setup.sql"
    "package.json"
    "nginx-sonrix.conf"
    "sonrix-voice.service"
    "server.js"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        missing_files+=("$file")
    fi
done

if [[ ${#missing_files[@]} -gt 0 ]]; then
    print_error "Eksik dosyalar:"
    for file in "${missing_files[@]}"; do
        echo "  ❌ $file"
    done
    echo ""
    print_error "Lütfen tüm dosyaları indirin ve tekrar deneyin."
    exit 1
fi

print_status "Tüm dosyalar mevcut ✅"

# Production config kontrolü
if [[ ! -f "production-config.sh" ]]; then
    print_error "production-config.sh dosyası bulunamadı!"
    exit 1
fi

# Config dosyasını yükle
source production-config.sh

# Konfigürasyonu doğrula
print_status "Konfigürasyon doğrulanıyor..."

if ! validate_config; then
    print_error "Konfigürasyon hatası!"
    echo ""
    echo "Lütfen production-config.sh dosyasını kontrol edin."
    exit 1
fi

print_status "Konfigürasyon geçerli ✅"

# Sistem güncellemesi
print_status "Sistem paketleri güncelleniyor..."
sudo apt update -q >/dev/null 2>&1

# Kurulum öncesi bilgi
echo -e "${BLUE}"
echo "=================================="
echo "     KURULUM BİLGİLERİ"
echo "=================================="
echo -e "${NC}"
echo -e "${YELLOW}Domain:${NC} $DOMAIN"
echo -e "${YELLOW}Server IP:${NC} $SERVER_IP"
echo -e "${YELLOW}Admin Email:${NC} $ADMIN_EMAIL"
echo -e "${YELLOW}SSL:${NC} $([[ "$ENABLE_SSL" == "yes" ]] && echo "Etkin" || echo "Devre dışı")"
echo -e "${YELLOW}Database:${NC} $DB_NAME"
echo -e "${YELLOW}Port:${NC} $APP_PORT"
echo ""

read -p "Kuruluma devam edilsin mi? (y/n) [y]: " CONTINUE
CONTINUE=${CONTINUE:-y}

if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
    print_warning "Kurulum iptal edildi."
    exit 0
fi

# .env dosyası oluştur
print_status ".env dosyası oluşturuluyor..."
generate_secrets
export_env

# Dosya izinlerini ayarla
chmod +x install-ubuntu.sh production-config.sh
chmod 600 .env

# Ana kurulum script'ini çalıştır
print_status "Ana kurulum başlatılıyor..."
echo ""

# Install script'e otomatik yanıtlar için environment değişkenleri ayarla
export SONRIX_AUTO_INSTALL="yes"
export SONRIX_DOMAIN="$DOMAIN"
export SONRIX_EMAIL="$ADMIN_EMAIL"
export SONRIX_DB_ROOT_PASSWORD="$DB_ROOT_PASSWORD"
export SONRIX_DB_USER_PASSWORD="$DB_USER_PASSWORD"
export SONRIX_SSL_ENABLED="$ENABLE_SSL"

# Kurulumu başlat
./install-ubuntu.sh

# Kurulum sonrası kontroller
print_status "Kurulum kontrolü yapılıyor..."

# PM2 durumu
if command -v pm2 >/dev/null 2>&1; then
    pm2_status=$(pm2 jlist 2>/dev/null | jq -r '.[0].pm2_env.status' 2>/dev/null || echo "unknown")
    if [[ "$pm2_status" == "online" ]]; then
        print_status "PM2 uygulaması çalışıyor ✅"
    else
        print_warning "PM2 uygulaması durumu: $pm2_status"
    fi
fi

# Nginx durumu
if systemctl is-active --quiet nginx; then
    print_status "Nginx çalışıyor ✅"
else
    print_warning "Nginx durumu kontrol edilmeli"
fi

# MySQL durumu
if systemctl is-active --quiet mysql; then
    print_status "MySQL çalışıyor ✅"
else
    print_warning "MySQL durumu kontrol edilmeli"
fi

# Port kontrolü
if netstat -tlnp 2>/dev/null | grep -q ":$APP_PORT "; then
    print_status "Port $APP_PORT dinleniyor ✅"
else
    print_warning "Port $APP_PORT kontrol edilmeli"
fi

# Kurulum tamamlandı
echo -e "${GREEN}"
echo "=================================="
echo "   KURULUM BAŞARIYLA TAMAMLANDI!"
echo "=================================="
echo -e "${NC}"

echo -e "${BLUE}🌍 Uygulama Adresleri:${NC}"
if [[ "$ENABLE_SSL" == "yes" ]]; then
    echo "   • Ana Site: https://$DOMAIN"
    echo "   • Admin Panel: https://$DOMAIN/admin.html"
    echo "   • Sesli Sohbet: https://$DOMAIN/voice-chat.html"
else
    echo "   • Ana Site: http://$DOMAIN"
    echo "   • Admin Panel: http://$DOMAIN/admin.html"
    echo "   • Sesli Sohbet: http://$DOMAIN/voice-chat.html"
fi

echo -e "${BLUE}👤 Admin Bilgileri:${NC}"
echo "   • Kullanıcı Adı: $ADMIN_USERNAME"
echo "   • Email: $ADMIN_EMAIL"
echo "   • Şifre: $ADMIN_PASSWORD"

echo -e "${BLUE}🔧 Servis Komutları:${NC}"
echo "   • Durum: pm2 status"
echo "   • Loglar: pm2 logs sonrix-voice"
echo "   • Yeniden başlat: pm2 restart sonrix-voice"
echo "   • Durdur: pm2 stop sonrix-voice"

echo -e "${BLUE}📊 Sistem İzleme:${NC}"
echo "   • PM2 Monitor: pm2 monit"
echo "   • Nginx Status: sudo systemctl status nginx"
echo "   • MySQL Status: sudo systemctl status mysql"

echo -e "${BLUE}🔐 Güvenlik Notları:${NC}"
echo "   • Admin şifrenizi güvenli bir yerde saklayın"
echo "   • .env dosyasını git'e eklemeyin"
echo "   • Düzenli yedekleme yapın"

echo -e "${BLUE}📝 İlk Adımlar:${NC}"
echo "   1. https://$DOMAIN adresine gidin"
echo "   2. Login sayfasından admin hesabı ile giriş yapın"
echo "   3. Admin panelinden sistem ayarlarını kontrol edin"
echo "   4. İlk test odasını oluşturun"

echo -e "${BLUE}🚨 Sorun Yaşarsanız:${NC}"
echo "   • Logları kontrol edin: pm2 logs"
echo "   • Servis durumunu kontrol edin: pm2 status"
echo "   • Sistem loglarını kontrol edin: sudo journalctl -u sonrix-voice"

echo ""
echo -e "${GREEN}🎉 Sonrix Voice başarıyla kuruldu ve çalışıyor!${NC}"
echo -e "${YELLOW}   Artık ses sohbet odaları oluşturabilir ve kullanabilirsiniz.${NC}"

# Final test (opsiyonel)
if command -v curl >/dev/null 2>&1; then
    print_status "Bağlantı testi yapılıyor..."
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$APP_PORT/health" | grep -q "200"; then
        print_status "Uygulama sağlık kontrolü başarılı ✅"
    else
        print_warning "Uygulama sağlık kontrolü başarısız - manuel kontrol gerekli"
    fi
fi
