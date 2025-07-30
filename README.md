# 🎤 Sonrix Voice - Production Kurulum Kılavuzu

**sonrix.tech** sunucusu için hazır konfigürasyon dosyaları ve kurulum talimatları.

## 🚀 Hızlı Kurulum (Tek Komut)

```bash
# 1. Dosyaları indirin ve dizine girin
git clone your-repo-url sonrix-voice
cd sonrix-voice

# 2. Kurulum izni verin
chmod +x *.sh

# 3. Tek komutla kurulumu başlatın
./quick-start.sh
```

## 📋 Manuel Kurulum

### 1. Ön Gereksinimler

- **Ubuntu 22.04 LTS** sunucu
- **Root erişimi** (sudo yetkisi)
- **Domain**: sonrix.tech (DNS ayarları yapılmış)
- **IP**: 45.147.46.196

### 2. Dosyaları Hazırlayın

```bash
# Repository'yi klonlayın
git clone your-repo-url sonrix-voice
cd sonrix-voice

# Dosya izinlerini ayarlayın
chmod +x install-ubuntu.sh
chmod +x production-config.sh
chmod +x quick-start.sh
```

### 3. Konfigürasyonu Kontrol Edin

```bash
# Production config'i çalıştırın
./production-config.sh

# .env dosyası oluşturulacak ve şu bilgiler görünecek:
# - Admin Kullanıcı: admin
# - Admin Şifre: SonrixAdmin2024!
# - Admin Email: admin@sonrix.tech
```

### 4. Kurulumu Başlatın

```bash
# Otomatik kurulum (önerilen)
./install-ubuntu.sh

# Kurulum sırasında otomatik olarak:
# ✅ Node.js 18 LTS
# ✅ MySQL 8.0
# ✅ Nginx
# ✅ SSL sertifikası (Let's Encrypt)
# ✅ PM2 process manager
# ✅ Firewall (UFW)
# ✅ Fail2ban
# ✅ Otomatik backup sistemi
```

## 🔧 Kurulum Sonrası

### Servis Durumu Kontrolü

```bash
# Uygulama durumu
pm2 status

# Nginx durumu  
sudo systemctl status nginx

# MySQL durumu
sudo systemctl status mysql

# Firewall durumu
sudo ufw status
```

### Logları İzleme

```bash
# Uygulama logları
pm2 logs sonrix-voice

# Nginx logları
sudo tail -f /var/log/nginx/sonrix-voice.access.log
sudo tail -f /var/log/nginx/sonrix-voice.error.log

# Sistem logları
sudo journalctl -u sonrix-voice -f
```

## 🌐 Erişim Adresleri

- **Ana Site**: https://sonrix.tech
- **Admin Panel**: https://sonrix.tech/admin.html
- **API**: https://sonrix.tech/api/
- **Health Check**: https://sonrix.tech/health

## 👤 Admin Bilgileri

```
Kullanıcı Adı: admin
Email: admin@sonrix.tech
Şifre: SonrixAdmin2024!
```

> ⚠️ **Güvenlik**: İlk girişten sonra admin şifresini değiştirin!

## 🔒 Güvenlik Ayarları

### Firewall Kuralları
```bash
# Açık portlar
sudo ufw status numbered

# Port 22 (SSH), 80 (HTTP), 443 (HTTPS), 3000 (App) açık olmalı
```

### SSL Sertifikası
```bash
# Sertifika durumu
sudo certbot certificates

# Manuel yenileme (otomatik zaten aktif)
sudo certbot renew --dry-run
```

### MySQL Güvenlik
```bash
# Root şifre: Arda6262!
# App şifre: Sonrix2024_App_DB_Pass!
mysql -u root -p
```

## 📊 Monitoring

### PM2 Monitoring
```bash
# Gerçek zamanlı monitoring
pm2 monit

# Detaylı bilgi
pm2 show sonrix-voice

# Memory ve CPU kullanımı
pm2 list
```

### Sistem Kaynakları
```bash
# Disk kullanımı
df -h

# Memory kullanımı
free -h

# CPU kullanımı
htop
```

## 🔄 Yedekleme

### Otomatik Yedekleme
```bash
# Yedekleme durumu (günlük 02:00'da çalışır)
crontab -l

# Manuel yedekleme
./backup.sh
```

### Yedekleme Konumu
```bash
# Yedekler burada saklanır
ls -la /var/backups/sonrix-voice/

# Son 30 günün yedekleri tutulur
```

## 🚨 Sorun Giderme

### Uygulama Çalışmıyor
```bash
# PM2 durumunu kontrol et
pm2 status

# Uygulamayı yeniden başlat
pm2 restart sonrix-voice

# Logları kontrol et
pm2 logs sonrix-voice --lines 50
```

### SSL Sertifikası Sorunu
```bash
# Nginx konfigürasyon testi
sudo nginx -t

# SSL sertifikası yenile
sudo certbot renew

# Nginx yeniden başlat
sudo systemctl restart nginx
```

### Veritabanı Bağlantı Sorunu
```bash
# MySQL servisini kontrol et
sudo systemctl status mysql

# Veritabanı bağlantısını test et
mysql -u sonrix_user -p sonrix_voice

# MySQL yeniden başlat
sudo systemctl restart mysql
```

### Port Bağlantı Sorunu
```bash
# Port kullanımını kontrol et
sudo netstat -tlnp | grep :3000
sudo netstat -tlnp | grep :80
sudo netstat -tlnp | grep :443

# Firewall kurallarını kontrol et
sudo ufw status verbose
```

## 🔄 Güncelleme

### Uygulama Güncellemesi
```bash
# Git pull
git pull origin main

# Bağımlılıkları güncelle
npm install

# PM2 ile yeniden başlat
pm2 restart sonrix-voice
```

### Sistem Güncellemesi
```bash
# Sistem paketlerini güncelle
sudo apt update && sudo apt upgrade -y

# Nginx güncelle
sudo apt install nginx

# Node.js güncelle (gerekirse)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

## 📝 Konfigürasyon Dosyaları

### Önemli Dosyalar
- `.env` - Uygulama ayarları
- `ecosystem.config.js` - PM2 konfigürasyonu  
- `/etc/nginx/sites-available/sonrix-voice` - Nginx konfigürasyonu
- `/etc/systemd/system/sonrix-voice.service` - Systemd service
- `ubuntu-mysql-setup.sql` - Veritabanı şeması

### Konfigürasyon Değişiklikleri
```bash
# .env dosyasını düzenle
nano .env

# Değişikliklerden sonra uygulamayı yeniden başlat
pm2 restart sonrix-voice
```

## 📞 Destek

### Log Dosyaları
- **Uygulama**: `./logs/app.log`
- **PM2**: `~/.pm2/logs/`
- **Nginx**: `/var/log/nginx/`
- **MySQL**: `/var/log/mysql/`

### Sistem Bilgileri
```bash
# Sistem bilgileri
uname -a
lsb_release -a

# Node.js sürümü
node --version
npm --version

# MySQL sürümü
mysql --version

# Nginx sürümü
nginx -v
```

## ✅ Kurulum Kontrolü

Kurulum başarılı ise:

1. ✅ https://sonrix.tech açılıyor
2. ✅ Admin paneline erişim var
3. ✅ SSL sertifikası çalışıyor
4. ✅ PM2'de uygulama çalışıyor
5. ✅ MySQL bağlantısı aktif
6. ✅ Nginx reverse proxy çalışıyor
7. ✅ Firewall aktif
8. ✅ Otomatik yedekleme kurulu

---

**🎉 Sonrix Voice başarıyla kuruldu!**

*Herhangi bir sorun yaşarsanız yukarıdaki sorun giderme adımlarını takip edin.*
