# 🎙️ Sonrix Voice Chat

WebRTC + Node.js + Socket.io tabanlı profesyonel sesli sohbet platformu.

## Özellikler

- 🎤 Gerçek zamanlı sesli iletişim (WebRTC)
- 🔒 JWT ile oturum yönetimi
- 📊 Admin paneli üzerinden kullanıcı ve oda yönetimi
- 🎥 Video, ekran paylaşımı, mesajlaşma türleri desteği
- 📁 MySQL tabanlı veri yönetimi
- 📦 Socket.IO ile gerçek zamanlı bağlantılar

## Kurulum

```bash
npm install
```

## Başlatma

```bash
node server.js
```

## Ortam Değişkenleri (.env)

```env
DB_HOST=localhost
DB_USER=root
DB_PASS=
DB_NAME=sonrix_chat
JWT_SECRET=anysecretkey
SESSION_SECRET=anysessionsecret
```
