const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const session = require('express-session');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'sonrix-voice-chat-secret-key-2025';
const SESSION_SECRET = process.env.SESSION_SECRET || 'sonrix-session-secret-2025';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // HTTPS için true yapın
        maxAge: 24 * 60 * 60 * 1000 // 24 saat
    }
}));

// Static files
app.use(express.static('public'));

// Database configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'sonrix_chat',
    charset: 'utf8mb4'
};

let db;

// Initialize database connection
async function initDatabase() {
    try {
        db = await mysql.createConnection(dbConfig);
        console.log('✅ Database connected successfully');
        
        // Test connection
        await db.execute('SELECT 1');
        
        // Start cleanup interval
        setInterval(cleanupExpiredMessages, 24 * 60 * 60 * 1000); // Daily cleanup
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        console.log('💡 Database configuration:', {
            host: dbConfig.host,
            user: dbConfig.user,
            database: dbConfig.database
        });
    }
}

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const token = req.session.token;
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied - No token' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [rows] = await db.execute('SELECT * FROM users WHERE id = ? AND is_active = true', [decoded.userId]);
        
        if (rows.length === 0) {
            return res.status(401).json({ error: 'User not found or inactive' });
        }
        
        req.user = rows[0];
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Routes
app.get('/', (req, res) => {
    if (req.session.token) {
        res.sendFile(path.join(__dirname, 'public', 'voice-chat.html'));
    } else {
        res.sendFile(path.join(__dirname, 'public', 'login.html'));
    }
});

app.get('/admin', authenticateToken, requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/user-info', authenticateToken, (req, res) => {
    res.json({
        id: req.user.id,
        username: req.user.username,
        role: req.user.role
    });
});

app.get('/api/auth-token', authenticateToken, (req, res) => {
    res.json({ token: req.session.token });
});

// Authentication routes
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        const [rows] = await db.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = true', 
            [username]
        );
        
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        // Update last login
        await db.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
        
        const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        req.session.token = token;
        
        res.json({ 
            success: true, 
            user: { 
                id: user.id, 
                username: user.username, 
                role: user.role 
            } 
        });
        
        console.log(`✅ User logged in: ${user.username} (${user.role})`);
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.post('/api/logout', (req, res) => {
    const username = req.session.username;
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
        } else {
            console.log(`✅ User logged out: ${username}`);
        }
    });
    res.json({ success: true });
});

// Admin API routes
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT u.id, u.username, u.email, u.role, u.is_active, u.created_at, u.last_login,
                   creator.username as created_by_name
            FROM users u
            LEFT JOIN users creator ON u.created_by = creator.id
            ORDER BY u.created_at DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        // Check if username exists
        const [existing] = await db.execute('SELECT id FROM users WHERE username = ?', [username]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        
        const [result] = await db.execute(`
            INSERT INTO users (username, password, email, created_by) 
            VALUES (?, ?, ?, ?)
        `, [username, hashedPassword, email || null, req.user.id]);
        
        console.log(`✅ User created: ${username} by ${req.user.username}`);
        res.json({ success: true, userId: result.insertId });
        
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

app.put('/api/admin/users/:id/toggle', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Don't allow disabling admin users
        const [user] = await db.execute('SELECT role, username FROM users WHERE id = ?', [userId]);
        if (user[0]?.role === 'admin') {
            return res.status(400).json({ error: 'Cannot disable admin user' });
        }
        
        await db.execute('UPDATE users SET is_active = NOT is_active WHERE id = ?', [userId]);
        console.log(`✅ User status toggled: ${user[0]?.username} by ${req.user.username}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Toggle user error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Don't allow deleting admin users
        const [user] = await db.execute('SELECT role, username FROM users WHERE id = ?', [userId]);
        if (user[0]?.role === 'admin') {
            return res.status(400).json({ error: 'Cannot delete admin user' });
        }
        
        await db.execute('DELETE FROM users WHERE id = ?', [userId]);
        console.log(`✅ User deleted: ${user[0]?.username} by ${req.user.username}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/rooms', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT r.*, u.username as created_by_name,
                   (SELECT COUNT(*) FROM user_sessions s WHERE s.room_id = r.id AND s.left_at IS NULL) as active_users
            FROM rooms r
            LEFT JOIN users u ON r.created_by = u.id
            ORDER BY r.created_at DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Get rooms error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/messages', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT m.*, u.username, r.room_code,
                   CASE 
                       WHEN m.expires_at IS NULL THEN 'Kalıcı'
                       WHEN m.expires_at > NOW() THEN DATE_FORMAT(m.expires_at, '%d.%m.%Y %H:%i')
                       ELSE 'Süresi Dolmuş'
                   END as expires_status
            FROM messages m
            LEFT JOIN users u ON m.user_id = u.id
            LEFT JOIN rooms r ON m.room_id = r.id
            WHERE m.is_admin_visible = true
            ORDER BY m.created_at DESC
            LIMIT 100
        `);
        res.json(rows);
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [userStats] = await db.execute(`
            SELECT COUNT(*) as total, SUM(is_active) as active 
            FROM users WHERE role != 'admin'
        `);
        
        const [roomStats] = await db.execute('SELECT COUNT(*) as total FROM rooms');
        
        const [messageStats] = await db.execute(`
            SELECT COUNT(*) as today 
            FROM messages WHERE DATE(created_at) = CURDATE()
        `);
        
        const [totalMessages] = await db.execute('SELECT COUNT(*) as total FROM messages');
        
        res.json({
            totalUsers: userStats[0].total || 0,
            activeUsers: userStats[0].active || 0,
            totalRooms: roomStats[0].total || 0,
            todayMessages: messageStats[0].today || 0,
            totalMessages: totalMessages[0].total || 0
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// WebRTC Socket.io with authentication
io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication error - No token'));
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const [rows] = await db.execute('SELECT * FROM users WHERE id = ? AND is_active = true', [decoded.userId]);
        
        if (rows.length === 0) {
            return next(new Error('User not found or inactive'));
        }
        
        socket.user = rows[0];
        next();
    } catch (error) {
        console.error('Socket authentication error:', error);
        next(new Error('Authentication failed'));
    }
});

// Active rooms and users tracking
const activeRooms = new Map();

io.on('connection', (socket) => {
    console.log(`✅ User connected: ${socket.user.username} (${socket.id})`);

    socket.on('join-room', async (data) => {
        try {
            const { roomCode } = data;
            
            if (!roomCode || roomCode.length > 20) {
                socket.emit('error', { message: 'Invalid room code' });
                return;
            }
            
            // Get or create room
            let [rooms] = await db.execute('SELECT * FROM rooms WHERE room_code = ?', [roomCode]);
            let room;
            
            if (rooms.length === 0) {
                const [result] = await db.execute(`
                    INSERT INTO rooms (room_code, room_name, created_by) 
                    VALUES (?, ?, ?)
                `, [roomCode, `Oda ${roomCode}`, socket.user.id]);
                
                room = { 
                    id: result.insertId, 
                    room_code: roomCode, 
                    room_name: `Oda ${roomCode}`,
                    created_by: socket.user.id
                };
                
                console.log(`🏠 Room created: ${roomCode} by ${socket.user.username}`);
            } else {
                room = rooms[0];
            }
            
            // Leave previous rooms
            Array.from(socket.rooms).forEach(roomId => {
                if (roomId !== socket.id) {
                    socket.leave(roomId);
                }
            });
            
            // Join new room
            socket.join(roomCode);
            socket.currentRoom = room;
            
            // Create session record
            const [sessionResult] = await db.execute(`
                INSERT INTO user_sessions (user_id, room_id, ip_address, user_agent) 
                VALUES (?, ?, ?, ?)
            `, [
                socket.user.id, 
                room.id, 
                socket.handshake.address || 'unknown',
                socket.handshake.headers['user-agent'] || 'unknown'
            ]);
            
            socket.sessionId = sessionResult.insertId;
            
            // Update active rooms tracking
            if (!activeRooms.has(roomCode)) {
                activeRooms.set(roomCode, new Map());
            }
            
            const roomUsers = activeRooms.get(roomCode);
            roomUsers.set(socket.id, {
                id: socket.user.id,
                username: socket.user.username,
                role: socket.user.role,
                socketId: socket.id,
                isMicOn: false,
                isVideoOn: false,
                joinedAt: new Date()
            });
            
            // Notify others in room
            socket.to(roomCode).emit('user-joined', {
                userId: socket.id,
                username: socket.user.username,
                role: socket.user.role
            });
            
            // Send current users to new joiner
            const users = Array.from(roomUsers.values()).filter(u => u.socketId !== socket.id);
            socket.emit('room-users', users);
            
            // Log join message
            await logMessage(room.id, socket.user.id, 'system', 
                `${socket.user.username} odaya katıldı`);
            
            console.log(`👤 ${socket.user.username} joined room ${roomCode} (${roomUsers.size} users total)`);
            
        } catch (error) {
            console.error('Join room error:', error);
            socket.emit('error', { message: 'Failed to join room' });
        }
    });

    // WebRTC signaling
    socket.on('offer', (data) => {
        socket.to(data.target).emit('offer', {
            offer: data.offer,
            sender: socket.id,
            senderUsername: socket.user.username
        });
        console.log(`📞 Offer sent: ${socket.user.username} -> target`);
    });

    socket.on('answer', (data) => {
        socket.to(data.target).emit('answer', {
            answer: data.answer,
            sender: socket.id
        });
        console.log(`📞 Answer sent: ${socket.user.username} -> target`);
    });

    socket.on('ice-candidate', (data) => {
        socket.to(data.target).emit('ice-candidate', {
            candidate: data.candidate,
            sender: socket.id
        });
    });

    // Media controls with logging
    socket.on('mic-toggle', async (isMicOn) => {
        if (socket.currentRoom) {
            const roomCode = socket.currentRoom.room_code;
            const roomUsers = activeRooms.get(roomCode);
            
            if (roomUsers && roomUsers.has(socket.id)) {
                roomUsers.get(socket.id).isMicOn = isMicOn;
                socket.to(roomCode).emit('user-mic-toggle', {
                    userId: socket.id,
                    isMicOn: isMicOn
                });
                
                // Log activity
                await logMessage(socket.currentRoom.id, socket.user.id, 'system', 
                    `${socket.user.username} mikrofonunu ${isMicOn ? 'açtı' : 'kapattı'}`);
                
                console.log(`🎤 ${socket.user.username} mic: ${isMicOn ? 'ON' : 'OFF'}`);
            }
        }
    });

    socket.on('video-toggle', async (isVideoOn) => {
        if (socket.currentRoom) {
            const roomCode = socket.currentRoom.room_code;
            const roomUsers = activeRooms.get(roomCode);
            
            if (roomUsers && roomUsers.has(socket.id)) {
                roomUsers.get(socket.id).isVideoOn = isVideoOn;
                socket.to(roomCode).emit('user-video-toggle', {
                    userId: socket.id,
                    isVideoOn: isVideoOn
                });
                
                // Log activity
                await logMessage(socket.currentRoom.id, socket.user.id, 'system', 
                    `${socket.user.username} kamerayı ${isVideoOn ? 'açtı' : 'kapattı'}`);
                
                console.log(`📹 ${socket.user.username} video: ${isVideoOn ? 'ON' : 'OFF'}`);
            }
        }
    });

    socket.on('disconnect', async () => {
        console.log(`❌ User disconnected: ${socket.user.username}`);
        
        // Update session end time
        if (socket.sessionId) {
            await db.execute(`
                UPDATE user_sessions 
                SET left_at = NOW(), 
                    duration_minutes = TIMESTAMPDIFF(MINUTE, joined_at, NOW()) 
                WHERE id = ?
            `, [socket.sessionId]);
        }
        
        // Remove from active rooms
        if (socket.currentRoom) {
            const roomCode = socket.currentRoom.room_code;
            const roomUsers = activeRooms.get(roomCode);
            
            if (roomUsers) {
                roomUsers.delete(socket.id);
                
                if (roomUsers.size === 0) {
                    activeRooms.delete(roomCode);
                    console.log(`🏠 Room ${roomCode} is now empty`);
                } else {
                    socket.to(roomCode).emit('user-left', {
                        userId: socket.id,
                        username: socket.user.username
                    });
                }
                
                // Log leave message
                await logMessage(socket.currentRoom.id, socket.user.id, 'system', 
                    `${socket.user.username} odadan ayrıldı`);
            }
        }
    });
});

// Helper functions
async function logMessage(roomId, userId, messageType, content, metadata = null) {
    try {
        // Set expiration (7 days for user messages, null for admin/system)
        const expiresAt = (messageType === 'system') ? null : 
            new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        
        await db.execute(`
            INSERT INTO messages (room_id, user_id, message_type, content, metadata, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?)
        `, [roomId, userId, messageType, content, JSON.stringify(metadata), expiresAt]);
        
    } catch (error) {
        console.error('Log message error:', error);
    }
}

async function cleanupExpiredMessages() {
    try {
        const [result] = await db.execute(`
            UPDATE messages 
            SET is_admin_visible = false 
            WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_admin_visible = true
        `);
        
        if (result.affectedRows > 0) {
            console.log(`🧹 Cleaned up ${result.affectedRows} expired messages`);
        }
    } catch (error) {
        console.error('Cleanup error:', error);
    }
}

// Error handling
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Initialize database and start server
initDatabase().then(() => {
    const PORT = process.env.PORT || 3000;
    const HOST = process.env.HOST || '0.0.0.0';
    
    server.listen(PORT, HOST, () => {
        console.log('🚀 =====================================');
        console.log('🎙️  SONRIX VOICE CHAT SERVER');
        console.log('🚀 =====================================');
        console.log(`📱 Local: http://localhost:${PORT}`);
        console.log(`🌐 Network: http://[your-ip]:${PORT}`);
        console.log(`👨‍💼 Admin Panel: http://[your-ip]:${PORT}/admin`);
        console.log('🚀 =====================================');
        console.log(`📊 Features: Auth, Admin Panel, WebRTC, Database`);
        console.log(`🗄️  Database: ${dbConfig.database}@${dbConfig.host}`);
        console.log('🚀 =====================================');
    });
}).catch((error) => {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
});