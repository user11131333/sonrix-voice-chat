-- Sonrix Voice Chat Database Setup
-- Bu dosyayı phpMyAdmin'de SQL sekmesinde çalıştırın

-- Database oluştur (eğer yoksa)
CREATE DATABASE IF NOT EXISTS sonrix_chat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sonrix_chat;

-- Users table
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
    INDEX idx_active (is_active),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Rooms table
CREATE TABLE rooms (
    id INT PRIMARY KEY AUTO_INCREMENT,
    room_code VARCHAR(20) UNIQUE NOT NULL,
    room_name VARCHAR(100) NULL,
    created_by INT NOT NULL,
    is_private BOOLEAN DEFAULT false,
    max_users INT DEFAULT 10,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_room_code (room_code),
    INDEX idx_created_by (created_by),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
);

-- Messages table
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
    INDEX idx_admin_visible (is_admin_visible),
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- User sessions table
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
    INDEX idx_active_sessions (room_id, left_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
);

-- Room permissions table (future use)
CREATE TABLE room_permissions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    room_id INT NOT NULL,
    user_id INT NOT NULL,
    can_speak BOOLEAN DEFAULT true,
    can_video BOOLEAN DEFAULT true,
    can_screen_share BOOLEAN DEFAULT true,
    granted_by INT NOT NULL,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_room_user (room_id, user_id),
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert default admin user (password: admin123)
INSERT INTO users (username, password, email, role) VALUES 
('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj7PW8w8VZau', 'admin@sonrix.tech', 'admin');

-- Insert demo user (password: demo123)
INSERT INTO users (username, password, email, role, created_by) VALUES 
('demo', '$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'demo@sonrix.tech', 'user', 1);

-- Insert default general room
INSERT INTO rooms (room_code, room_name, created_by) VALUES 
('GENERAL', 'Genel Sohbet Odası', 1);

-- Insert welcome message
INSERT INTO messages (room_id, user_id, message_type, content) VALUES 
(1, 1, 'system', 'Sonrix Voice Chat platformuna hoş geldiniz! Bu sistem mesajıdır.');

-- Views for easier data access
CREATE VIEW active_users_view AS
SELECT u.id, u.username, u.email, u.role, u.last_login,
       CASE WHEN s.user_id IS NOT NULL THEN true ELSE false END as is_online
FROM users u
LEFT JOIN user_sessions s ON u.id = s.user_id AND s.left_at IS NULL
WHERE u.is_active = true;

CREATE VIEW room_stats_view AS
SELECT r.id, r.room_code, r.room_name, 
       COUNT(DISTINCT s.user_id) as active_users,
       COUNT(DISTINCT m.id) as total_messages,
       r.created_at
FROM rooms r
LEFT JOIN user_sessions s ON r.id = s.room_id AND s.left_at IS NULL
LEFT JOIN messages m ON r.id = m.room_id
GROUP BY r.id, r.room_code, r.room_name, r.created_at;

-- Stored procedure for message cleanup
DELIMITER //
CREATE PROCEDURE CleanupExpiredMessages()
BEGIN
    UPDATE messages 
    SET is_admin_visible = false 
    WHERE expires_at IS NOT NULL 
    AND expires_at < NOW() 
    AND is_admin_visible = true;
    
    SELECT ROW_COUNT() as cleaned_messages;
END //
DELIMITER ;

-- Event scheduler for automatic cleanup (MySQL 5.1+)
SET GLOBAL event_scheduler = ON;

CREATE EVENT IF NOT EXISTS cleanup_messages_event
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanupExpiredMessages();

-- Final data verification
SELECT 'Database setup completed successfully!' as status;
SELECT COUNT(*) as user_count FROM users;
SELECT COUNT(*) as room_count FROM rooms;
SELECT COUNT(*) as message_count FROM messages;

-- Show default login credentials
SELECT 'DEFAULT LOGIN CREDENTIALS:' as info;
SELECT username, 'admin123' as password, role FROM users WHERE role = 'admin';
SELECT username, 'demo123' as password, role FROM users WHERE role = 'user';-- Sonrix Voice Chat Database Setup
-- Bu dosyayı phpMyAdmin'de SQL sekmesinde çalıştırın

-- Database oluştur (eğer yoksa)
CREATE DATABASE IF NOT EXISTS sonrix_chat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sonrix_chat;

-- Users table
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
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Rooms table
CREATE TABLE rooms (
    id INT PRIMARY KEY AUTO_INCREMENT,
    room_code VARCHAR(20) UNIQUE NOT NULL,
    room_name VARCHAR(100) NULL,
    created_by INT NOT NULL,
    is_private BOOLEAN DEFAULT false,
    max_users INT DEFAULT 10,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
);

-- Messages table
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
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- User sessions table
CREATE TABLE user_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    room_id INT NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP NULL