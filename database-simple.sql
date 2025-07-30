-- Sonrix Voice - Basit Database Şeması
-- Ubuntu 22.04 + MySQL 8.0 için optimize edilmiş

CREATE DATABASE IF NOT EXISTS sonrix_voice CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sonrix_voice;

-- Kullanıcı oluştur
CREATE USER IF NOT EXISTS 'sonrix_user'@'localhost' IDENTIFIED WITH mysql_native_password BY 'Sonrix2024_App_DB_Pass!';
GRANT ALL PRIVILEGES ON sonrix_voice.* TO 'sonrix_user'@'localhost';
FLUSH PRIVILEGES;

-- =======================
-- BASIT TABLO YAPILARI
-- =======================

-- Kullanıcılar tablosu
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NULL,
    role ENUM('admin', 'user') DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    created_by INT NULL,
    INDEX idx_username (username),
    INDEX idx_role (role),
    INDEX idx_active (is_active)
);

-- Odalar tablosu
CREATE TABLE rooms (
    id INT PRIMARY KEY AUTO_INCREMENT,
    room_code VARCHAR(20) UNIQUE NOT NULL,
    room_name VARCHAR(100) NULL,
    created_by INT NOT NULL,
    is_private BOOLEAN DEFAULT false,
    password VARCHAR(255) NULL,
    max_users INT DEFAULT 10,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_room_code (room_code),
    INDEX idx_created_by (created_by)
);

-- Mesajlar tablosu
CREATE TABLE messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    room_id INT NOT NULL,
    user_id INT NOT NULL,
    message_type ENUM('text', 'voice', 'video', 'screen_share', 'system') DEFAULT 'system',
    content TEXT NULL,
    metadata JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    is_admin_visible BOOLEAN DEFAULT true,
    INDEX idx_room_created (room_id, created_at),
    INDEX idx_expires (expires_at),
    INDEX idx_admin_visible (is_admin_visible)
);

-- Kullanıcı oturumları tablosu
CREATE TABLE user_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    room_id INT NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP NULL,
    duration_minutes INT DEFAULT 0,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    INDEX idx_user_room (user_id, room_id),
    INDEX idx_active_sessions (room_id, left_at)
);

-- =======================
-- BAŞLANGIÇ VERİLERİ
-- =======================

-- Admin kullanıcısı (şifre: admin123)
INSERT INTO users (username, password, email, role) VALUES 
('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj7PW8w8VZau', 'admin@sonrix.tech', 'admin');

-- Demo kullanıcısı (şifre: demo123)  
INSERT INTO users (username, password, email, role, created_by) VALUES 
('demo', '$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'demo@sonrix.tech', 'user', 1);

-- Genel oda
INSERT INTO rooms (room_code, room_name, created_by) VALUES 
('GENERAL', 'Genel Sohbet Odası', 1);

-- Hoş geldin mesajı
INSERT INTO messages (room_id, user_id, message_type, content) VALUES 
(1, 1, 'system', 'Sonrix Voice Chat platformuna hoş geldiniz!');

-- =======================
-- VIEWS (İsteğe bağlı)
-- =======================

-- Aktif kullanıcılar
CREATE VIEW active_users_view AS
SELECT u.id, u.username, u.email, u.role, u.last_login,
       CASE WHEN s.user_id IS NOT NULL THEN true ELSE false END as is_online
FROM users u
LEFT JOIN user_sessions s ON u.id = s.user_id AND s.left_at IS NULL
WHERE u.is_active = true;

-- Oda istatistikleri
CREATE VIEW room_stats_view AS
SELECT r.id, r.room_code, r.room_name, 
       COUNT(DISTINCT s.user_id) as active_users,
       COUNT(DISTINCT m.id) as total_messages,
       r.created_at
FROM rooms r
LEFT JOIN user_sessions s ON r.id = s.room_id AND s.left_at IS NULL
LEFT JOIN messages m ON r.id = m.room_id
GROUP BY r.id, r.room_code, r.room_name, r.created_at;

-- =======================
-- CLEANUP PROCEDURE
-- =======================

DELIMITER //
CREATE PROCEDURE CleanupOldData()
BEGIN
    -- Eski mesajları gizle (7 günden eski ones)
    UPDATE messages 
    SET is_admin_visible = false 
    WHERE expires_at IS NOT NULL 
    AND expires_at < NOW() 
    AND is_admin_visible = true;
    
    -- Eski oturumları temizle (30 günden eski)
    DELETE FROM user_sessions 
    WHERE left_at IS NOT NULL
    AND left_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
    
    SELECT ROW_COUNT() as cleaned_records;
END //
DELIMITER ;

-- =======================
-- EVENT SCHEDULER
-- =======================

SET GLOBAL event_scheduler = ON;

CREATE EVENT IF NOT EXISTS daily_cleanup
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanupOldData();

-- =======================
-- BAŞARIYLA TAMAMLANDI
-- =======================

SELECT 'Sonrix Voice basit veritabanı başarıyla kuruldu!' as 'Durum';
SELECT 'Admin: admin/admin123, Demo: demo/demo123' as 'Giriş Bilgileri';
