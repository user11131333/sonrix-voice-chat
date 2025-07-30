-- Sonrix Voice - MySQL 8.0 Optimized Database Setup
-- Ubuntu 22.04 LTS için optimize edilmiş

-- Charset ve collation ayarları
SET NAMES utf8mb4;
SET character_set_client = utf8mb4;

-- Veritabanı oluştur
CREATE DATABASE IF NOT EXISTS sonrix_voice 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- Veritabanını seç
USE sonrix_voice;

-- Kullanıcı oluştur ve izinleri ver
CREATE USER IF NOT EXISTS 'sonrix_user'@'localhost' IDENTIFIED WITH mysql_native_password BY 'PLACEHOLDER_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX ON sonrix_voice.* TO 'sonrix_user'@'localhost';
FLUSH PRIVILEGES;

-- =======================
-- TABLO YAPILARI
-- =======================

-- Kullanıcılar tablosu
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NULL,
    avatar_url VARCHAR(500) NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token VARCHAR(100) NULL,
    reset_token VARCHAR(100) NULL,
    reset_token_expires TIMESTAMP NULL,
    last_login TIMESTAMP NULL,
    login_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMP NULL,
    preferences JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_is_active (is_active),
    INDEX idx_last_login (last_login),
    INDEX idx_verification_token (verification_token),
    INDEX idx_reset_token (reset_token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Odalar tablosu
CREATE TABLE IF NOT EXISTS rooms (
    id VARCHAR(36) NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT NULL,
    creator_id BIGINT UNSIGNED NOT NULL,
    password_hash VARCHAR(255) NULL,
    is_private BOOLEAN NOT NULL DEFAULT FALSE,
    is_persistent BOOLEAN NOT NULL DEFAULT FALSE,
    max_users TINYINT UNSIGNED NOT NULL DEFAULT 10,
    current_users TINYINT UNSIGNED NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    settings JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    
    PRIMARY KEY (id),
    FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_creator_id (creator_id),
    INDEX idx_is_active (is_active),
    INDEX idx_is_private (is_private),
    INDEX idx_created_at (created_at),
    INDEX idx_expires_at (expires_at),
    FULLTEXT idx_name_description (name, description)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Oda katılımcıları tablosu
CREATE TABLE IF NOT EXISTS room_participants (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    room_id VARCHAR(36) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    role ENUM('member', 'moderator', 'admin') NOT NULL DEFAULT 'member',
    is_muted BOOLEAN NOT NULL DEFAULT FALSE,
    is_deafened BOOLEAN NOT NULL DEFAULT FALSE,
    is_speaking BOOLEAN NOT NULL DEFAULT FALSE,
    connection_quality ENUM('poor', 'fair', 'good', 'excellent') NOT NULL DEFAULT 'good',
    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP NULL,
    total_duration INT UNSIGNED NOT NULL DEFAULT 0,
    
    PRIMARY KEY (id),
    UNIQUE KEY uk_room_user (room_id, user_id),
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_room_id (room_id),
    INDEX idx_user_id (user_id),
    INDEX idx_joined_at (joined_at),
    INDEX idx_left_at (left_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Oturumlar tablosu
CREATE TABLE IF NOT EXISTS user_sessions (
    id VARCHAR(128) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NOT NULL,
    socket_id VARCHAR(100) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_activity TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_socket_id (socket_id),
    INDEX idx_is_active (is_active),
    INDEX idx_last_activity (last_activity),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sistem logları tablosu
CREATE TABLE IF NOT EXISTS system_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    level ENUM('error', 'warn', 'info', 'debug') NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    meta JSON NULL,
    user_id BIGINT UNSIGNED NULL,
    room_id VARCHAR(36) NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE SET NULL,
    INDEX idx_level (level),
    INDEX idx_user_id (user_id),
    INDEX idx_room_id (room_id),
    INDEX idx_created_at (created_at),
    FULLTEXT idx_message (message)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sistem ayarları tablosu
CREATE TABLE IF NOT EXISTS system_settings (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value JSON NOT NULL,
    description TEXT NULL,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by BIGINT UNSIGNED NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE KEY uk_setting_key (setting_key),
    INDEX idx_is_public (is_public),
    INDEX idx_updated_at (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Oda geçmişi tablosu (istatistikler için)
CREATE TABLE IF NOT EXISTS room_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    room_id VARCHAR(36) NOT NULL,
    event_type ENUM('created', 'joined', 'left', 'deleted', 'settings_changed') NOT NULL,
    user_id BIGINT UNSIGNED NULL,
    event_data JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_room_id (room_id),
    INDEX idx_event_type (event_type),
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Kullanıcı istatistikleri tablosu
CREATE TABLE IF NOT EXISTS user_statistics (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    stat_date DATE NOT NULL,
    rooms_created INT UNSIGNED NOT NULL DEFAULT 0,
    rooms_joined INT UNSIGNED NOT NULL DEFAULT 0,
    total_voice_time INT UNSIGNED NOT NULL DEFAULT 0, -- saniye cinsinden
    messages_sent INT UNSIGNED NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    UNIQUE KEY uk_user_date (user_id, stat_date),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_stat_date (stat_date),
    INDEX idx_updated_at (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =======================
-- VİEWLAR
-- =======================

-- Aktif odalar görünümü
CREATE OR REPLACE VIEW active_rooms AS
SELECT 
    r.*,
    u.username as creator_username,
    u.full_name as creator_full_name,
    COUNT(rp.user_id) as participant_count
FROM rooms r
JOIN users u ON r.creator_id = u.id
LEFT JOIN room_participants rp ON r.id = rp.room_id AND rp.left_at IS NULL
WHERE r.is_active = TRUE 
  AND (r.expires_at IS NULL OR r.expires_at > NOW())
GROUP BY r.id, u.username, u.full_name;

-- Çevrimiçi kullanıcılar görünümü
CREATE OR REPLACE VIEW online_users AS
SELECT 
    u.id,
    u.username,
    u.full_name,
    u.avatar_url,
    us.socket_id,
    us.last_activity,
    r.name as current_room_name,
    rp.is_muted,
    rp.is_speaking
FROM users u
JOIN user_sessions us ON u.id = us.user_id
LEFT JOIN room_participants rp ON u.id = rp.user_id AND rp.left_at IS NULL
LEFT JOIN rooms r ON rp.room_id = r.id
WHERE us.is_active = TRUE 
  AND us.last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
  AND u.is_active = TRUE;

-- Oda istatistikleri görünümü
CREATE OR REPLACE VIEW room_statistics AS
SELECT 
    r.id,
    r.name,
    r.creator_id,
    COUNT(DISTINCT rp.user_id) as total_participants,
    COUNT(DISTINCT CASE WHEN rp.left_at IS NULL THEN rp.user_id END) as current_participants,
    AVG(rp.total_duration) as avg_duration,
    MAX(rp.joined_at) as last_activity,
    r.created_at
FROM rooms r
LEFT JOIN room_participants rp ON r.id = rp.room_id
GROUP BY r.id, r.name, r.creator_id, r.created_at;

-- =======================
-- STORED PROCEDURE'LER
-- =======================

-- Kullanıcı oturumu temizleme
DELIMITER //
CREATE PROCEDURE CleanExpiredSessions()
BEGIN
    DELETE FROM user_sessions 
    WHERE expires_at < NOW() OR last_activity < DATE_SUB(NOW(), INTERVAL 1 DAY);
    
    SELECT ROW_COUNT() as cleaned_sessions;
END //
DELIMITER ;

-- Pasif odaları temizle
DELIMITER //
CREATE PROCEDURE CleanInactiveRooms()
BEGIN
    -- Süresi dolmuş odaları sil
    DELETE FROM rooms 
    WHERE expires_at IS NOT NULL AND expires_at < NOW();
    
    -- Katılımcısı olmayan odaları sil (persistent olmayanlar)
    DELETE r FROM rooms r
    LEFT JOIN room_participants rp ON r.id = rp.room_id AND rp.left_at IS NULL
    WHERE rp.room_id IS NULL 
      AND r.is_persistent = FALSE
      AND r.created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);
    
    SELECT ROW_COUNT() as cleaned_rooms;
END //
DELIMITER ;

-- Kullanıcı istatistiklerini güncelle
DELIMITER //
CREATE PROCEDURE UpdateUserStatistics(IN p_user_id BIGINT UNSIGNED)
BEGIN
    DECLARE v_stat_date DATE DEFAULT CURDATE();
    
    INSERT INTO user_statistics (user_id, stat_date, rooms_created, rooms_joined, total_voice_time)
    VALUES (p_user_id, v_stat_date, 0, 0, 0)
    ON DUPLICATE KEY UPDATE
        rooms_created = (
            SELECT COUNT(*) FROM rooms 
            WHERE creator_id = p_user_id AND DATE(created_at) = v_stat_date
        ),
        rooms_joined = (
            SELECT COUNT(*) FROM room_participants 
            WHERE user_id = p_user_id AND DATE(joined_at) = v_stat_date
        ),
        total_voice_time = (
            SELECT COALESCE(SUM(total_duration), 0) FROM room_participants 
            WHERE user_id = p_user_id AND DATE(joined_at) = v_stat_date
        );
END //
DELIMITER ;

-- =======================
-- TRİGGERLAR
-- =======================

-- Oda oluşturulduğunda geçmişe kaydet
DELIMITER //
CREATE TRIGGER room_created_trigger
AFTER INSERT ON rooms
FOR EACH ROW
BEGIN
    INSERT INTO room_history (room_id, event_type, user_id, event_data)
    VALUES (NEW.id, 'created', NEW.creator_id, JSON_OBJECT('room_name', NEW.name));
END //
DELIMITER ;

-- Odaya katılım geçmişi
DELIMITER //
CREATE TRIGGER room_participant_joined_trigger
AFTER INSERT ON room_participants
FOR EACH ROW
BEGIN
    INSERT INTO room_history (room_id, event_type, user_id)
    VALUES (NEW.room_id, 'joined', NEW.user_id);
    
    -- Oda katılımcı sayısını güncelle
    UPDATE rooms 
    SET current_users = (
        SELECT COUNT(*) FROM room_participants 
        WHERE room_id = NEW.room_id AND left_at IS NULL
    )
    WHERE id = NEW.room_id;
END //
DELIMITER ;

-- Odadan ayrılma geçmişi
DELIMITER //
CREATE TRIGGER room_participant_left_trigger
AFTER UPDATE ON room_participants
FOR EACH ROW
BEGIN
    IF NEW.left_at IS NOT NULL AND OLD.left_at IS NULL THEN
        INSERT INTO room_history (room_id, event_type, user_id)
        VALUES (NEW.room_id, 'left', NEW.user_id);
        
        -- Oda katılımcı sayısını güncelle
        UPDATE rooms 
        SET current_users = (
            SELECT COUNT(*) FROM room_participants 
            WHERE room_id = NEW.room_id AND left_at IS NULL
        )
        WHERE id = NEW.room_id;
        
        -- Toplam süreyi hesapla
        UPDATE room_participants 
        SET total_duration = TIMESTAMPDIFF(SECOND, joined_at, left_at)
        WHERE id = NEW.id AND total_duration = 0;
    END IF;
END //
DELIMITER ;

-- =======================
-- BAŞLANGIÇ VERİLERİ
-- =======================

-- Sistem ayarları
INSERT INTO system_settings (setting_key, setting_value, description, is_public) VALUES
('app_name', '"Sonrix Voice"', 'Uygulama adı', TRUE),
('app_version', '"2.0.0"', 'Uygulama sürümü', TRUE),
('max_room_users', '20', 'Odada maksimum kullanıcı sayısı', TRUE),
('max_rooms_per_user', '3', 'Kullanıcı başına maksimum oda sayısı', TRUE),
('room_timeout_minutes', '30', 'Oda otomatik kapatma süresi (dakika)', TRUE),
('registration_enabled', 'true', 'Yeni kayıt kabul edilsin mi', TRUE),
('maintenance_mode', 'false', 'Bakım modu', FALSE),
('voice_quality_default', '"medium"', 'Varsayılan ses kalitesi', TRUE),
('max_username_length', '50', 'Maksimum kullanıcı adı uzunluğu', TRUE),
('min_password_length', '8', 'Minimum şifre uzunluğu', TRUE),
('session_timeout_minutes', '30', 'Oturum zaman aşımı (dakika)', FALSE),
('log_retention_days', '90', 'Log saklama süresi (gün)', FALSE),
('cleanup_interval_minutes', '5', 'Temizlik görevi çalışma aralığı (dakika)', FALSE),
('stun_servers', '["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"]', 'STUN sunucuları', TRUE),
('turn_servers', '[]', 'TURN sunucuları', FALSE)
ON DUPLICATE KEY UPDATE 
    setting_value = VALUES(setting_value),
    updated_at = CURRENT_TIMESTAMP;

-- =======================
-- İNDEKS OPTİMİZASYONLARI
-- =======================

-- Composite indexler
ALTER TABLE room_participants ADD INDEX idx_room_left_at (room_id, left_at);
ALTER TABLE user_sessions ADD INDEX idx_user_active (user_id, is_active);
ALTER TABLE system_logs ADD INDEX idx_level_created (level, created_at);
ALTER TABLE room_history ADD INDEX idx_room_event_created (room_id, event_type, created_at);

-- Covering indexler (MySQL 8.0 invisible index özelliği)
ALTER TABLE users ADD INDEX idx_username_active_email (username, is_active, email);
ALTER TABLE rooms ADD INDEX idx_active_private_created (is_active, is_private, created_at);

-- =======================
-- PERFORMANs OPTİMİZASYONLARI
-- =======================

-- MySQL 8.0 ayarları
SET GLOBAL innodb_buffer_pool_size = 1073741824; -- 1GB
SET GLOBAL innodb_log_file_size = 268435456; -- 256MB
SET GLOBAL innodb_flush_log_at_trx_commit = 2;
SET GLOBAL innodb_flush_method = 'O_DIRECT';
SET GLOBAL max_connections = 200;
SET GLOBAL query_cache_type = 0; -- MySQL 8.0'da deprecated
SET GLOBAL tmp_table_size = 67108864; -- 64MB
SET GLOBAL max_heap_table_size = 67108864; -- 64MB

-- =======================
-- EVENT SCHEDULER (Otomatik temizlik)
-- =======================

-- Event scheduler'ı etkinleştir
SET GLOBAL event_scheduler = ON;

-- Günlük temizlik event'i
CREATE EVENT IF NOT EXISTS daily_cleanup
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO
BEGIN
    -- Eski oturumları temizle
    CALL CleanExpiredSessions();
    
    -- Pasif odaları temizle
    CALL CleanInactiveRooms();
    
    -- Eski logları temizle (90 günden eski)
    DELETE FROM system_logs 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
    
    -- Eski room history'yi temizle (1 yıldan eski)
    DELETE FROM room_history 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 YEAR);
    
    -- İstatistik tabloları optimize et
    OPTIMIZE TABLE users, rooms, room_participants, user_sessions, system_logs;
    
    -- Log kaydı
    INSERT INTO system_logs (level, message, meta) 
    VALUES ('info', 'Daily cleanup completed', JSON_OBJECT('timestamp', NOW()));
END;

-- Saatlik küçük temizlik event'i
CREATE EVENT IF NOT EXISTS hourly_maintenance
ON SCHEDULE EVERY 1 HOUR
STARTS CURRENT_TIMESTAMP
DO
BEGIN
    -- Sadece son 5 dakikada aktif olmayan oturumları işaretle
    UPDATE user_sessions 
    SET is_active = FALSE 
    WHERE is_active = TRUE 
      AND last_activity < DATE_SUB(NOW(), INTERVAL 5 MINUTE);
    
    -- Boş odaları temizle (persistent olmayanlar)
    UPDATE rooms r
    LEFT JOIN room_participants rp ON r.id = rp.room_id AND rp.left_at IS NULL
    SET r.is_active = FALSE
    WHERE rp.room_id IS NULL 
      AND r.is_persistent = FALSE 
      AND r.is_active = TRUE
      AND r.created_at < DATE_SUB(NOW(), INTERVAL 30 MINUTE);
END;

-- =======================
-- GÜVENLİK AYARLARI
-- =======================

-- Kullanıcı güvenlik fonksiyonları
DELIMITER //
CREATE FUNCTION IsValidPassword(password_text VARCHAR(255)) 
RETURNS BOOLEAN
READS SQL DATA
DETERMINISTIC
BEGIN
    DECLARE result BOOLEAN DEFAULT FALSE;
    
    -- En az 8 karakter
    IF LENGTH(password_text) >= 8 THEN
        SET result = TRUE;
    END IF;
    
    RETURN result;
END //

CREATE FUNCTION GenerateRoomId() 
RETURNS VARCHAR(36)
READS SQL DATA
DETERMINISTIC
BEGIN
    RETURN UUID();
END //

CREATE FUNCTION IsRoomNameValid(room_name VARCHAR(100))
RETURNS BOOLEAN
READS SQL DATA
DETERMINISTIC
BEGIN
    DECLARE result BOOLEAN DEFAULT FALSE;
    
    -- 3-100 karakter arası, sadece harf, rakam, boşluk ve bazı özel karakterler
    IF LENGTH(TRIM(room_name)) >= 3 
       AND LENGTH(TRIM(room_name)) <= 100
       AND room_name REGEXP '^[a-zA-Z0-9ğüşıöçĞÜŞİÖÇ ._-]+ THEN
        SET result = TRUE;
    END IF;
    
    RETURN result;
END //
DELIMITER ;

-- =======================
-- MONITORING VE LOGGING
-- =======================

-- Performans monitoring tablosu
CREATE TABLE IF NOT EXISTS performance_metrics (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(15,4) NOT NULL,
    metric_unit VARCHAR(20) NOT NULL,
    recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    INDEX idx_metric_name_recorded (metric_name, recorded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Rate limiting tablosu
CREATE TABLE IF NOT EXISTS rate_limits (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    identifier VARCHAR(100) NOT NULL, -- IP, user_id vs
    action_type VARCHAR(50) NOT NULL, -- login, create_room vs
    attempt_count INT UNSIGNED NOT NULL DEFAULT 1,
    window_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP NULL,
    
    PRIMARY KEY (id),
    UNIQUE KEY uk_identifier_action (identifier, action_type),
    INDEX idx_window_start (window_start),
    INDEX idx_blocked_until (blocked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =======================
-- BACKUP VE RESTORE PROCEDURE'LER
-- =======================

-- Backup metadata tablosu
CREATE TABLE IF NOT EXISTS backup_metadata (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    backup_type ENUM('full', 'incremental', 'differential') NOT NULL,
    backup_path VARCHAR(500) NOT NULL,
    backup_size BIGINT UNSIGNED NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    restored_at TIMESTAMP NULL,
    
    PRIMARY KEY (id),
    INDEX idx_backup_type (backup_type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =======================
-- SON KONTROLLER
-- =======================

-- Tablo boyutlarını kontrol et
SELECT 
    TABLE_NAME as 'Tablo',
    ROUND(((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024), 2) as 'Boyut (MB)',
    TABLE_ROWS as 'Satır Sayısı'
FROM information_schema.TABLES 
WHERE TABLE_SCHEMA = 'sonrix_voice'
ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC;

-- İndeks kullanımını kontrol et
SELECT 
    TABLE_NAME as 'Tablo',
    INDEX_NAME as 'İndeks',
    COLUMN_NAME as 'Sütun',
    CARDINALITY as 'Benzersizlik'
FROM information_schema.STATISTICS 
WHERE TABLE_SCHEMA = 'sonrix_voice'
ORDER BY TABLE_NAME, INDEX_NAME;

-- Foreign key kontrolü
SELECT 
    TABLE_NAME as 'Tablo',
    COLUMN_NAME as 'Sütun', 
    CONSTRAINT_NAME as 'Kısıt',
    REFERENCED_TABLE_NAME as 'Referans Tablo',
    REFERENCED_COLUMN_NAME as 'Referans Sütun'
FROM information_schema.KEY_COLUMN_USAGE 
WHERE TABLE_SCHEMA = 'sonrix_voice' 
  AND REFERENCED_TABLE_SCHEMA = 'sonrix_voice'
ORDER BY TABLE_NAME;

-- =======================
-- BAŞARIYLA TAMAMLANDI
-- =======================

-- Kurulum logunu kaydet
INSERT INTO system_logs (level, message, meta) 
VALUES (
    'info', 
    'Database setup completed successfully', 
    JSON_OBJECT(
        'version', '2.0.0',
        'mysql_version', VERSION(),
        'setup_date', NOW(),
        'charset', 'utf8mb4',
        'collation', 'utf8mb4_unicode_ci'
    )
);

-- Başarı mesajı
SELECT 
    'Sonrix Voice veritabanı başarıyla kuruldu!' as 'Durum',
    VERSION() as 'MySQL Sürümü',
    COUNT(*) as 'Oluşturulan Tablo Sayısı'
FROM information_schema.TABLES 
WHERE TABLE_SCHEMA = 'sonrix_voice';

-- Güvenlik uyarısı
SELECT 
    'UYARI: Kurulum tamamlandıktan sonra veritabanı şifrelerini değiştirmeyi unutmayın!' as 'Güvenlik Uyarısı';

-- Son kullanım talimatları
SELECT CONCAT(
    'Kurulum tamamlandı. ',
    'Uygulama .env dosyasında DB_PASSWORD değerini güncelleyin. ',
    'Daha sonra "npm start" komutu ile uygulamayı başlatabilirsiniz.'
) as 'Son Adımlar';
