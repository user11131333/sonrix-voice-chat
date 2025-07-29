require('dotenv').config();

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: process.env.NODE_ENV === 'production' ? false : "*",
        methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling']
});

// Security Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'sonrix-voice-chat-secret-key-ubuntu-2025';
const SESSION_SECRET = process.env.SESSION_SECRET || 'sonrix-session-secret-ubuntu-2025';

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", "ws:", "wss:"]
        }
    }
}));

app.use(compression());

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session middleware
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production' && process.env.HTTPS === 'true',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        httpOnly: true
    }
}));

// Static files
app.use(express.static('public', {
    maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0
}));

// MySQL 8.0 Connection Configuration (Ubuntu 22.04 Optimized)
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'sonrix_chat',
    charset: 'utf8mb4',
    // MySQL 8.0 specific settings
    authPlugins: {
        mysql_native_password: () => mysql.authPlugins.mysql_native_password,
        caching_sha2_password: () => mysql.authPlugins.caching_sha2_password
    },
    // Connection pool settings for better performance
    connectionLimit: 10,
    acquireTimeout: 60000,
    timeout: 60000,
    reconnect: true,
    // Ubuntu MySQL socket path (fallback)
    socketPath: process.env.MYSQL_SOCKET || '/var/run/mysqld/mysqld.sock'
};

let db;

// Database connection with retry logic
async function initDatabase(retries = 5) {
    try {
        console.log('🔄 Connecting to MySQL 8.0...');
        db = await mysql.createConnection(dbConfig);
        
        // Test connection
        await db.execute('SELECT 1 as test');
        console.log('✅ MySQL 8.0 connection established successfully');
        console.log(`📊 Database: ${dbConfig.database}@${dbConfig.host}`);
        
        // Setup connection error handling
        db.on('error', async (err) => {
            console.error('Cleanup error:', error);
    }
}

// Graceful shutdown handling
process.on('SIGTERM', async () => {
    console.log('🔄 SIGTERM received, shutting down gracefully...');
    server.close(() => {
        console.log('🛑 HTTP server closed');
        if (db) {
            db.end(() => {
                console.log('🗄️ Database connection closed');
                process.exit(0);
            });
        } else {
            process.exit(0);
        }
    });
});

process.on('SIGINT', async () => {
    console.log('🔄 SIGINT received, shutting down gracefully...');
    server.close(() => {
        console.log('🛑 HTTP server closed');
        if (db) {
            db.end(() => {
                console.log('🗄️ Database connection closed');
                process.exit(0);
            });
        } else {
            process.exit(0);
        }
    });
});

// Error handling
process.on('uncaughtException', (error) => {
    console.error('💥 Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

// Initialize database and start server
initDatabase().then(() => {
    const PORT = process.env.PORT || 3000;
    const HOST = process.env.HOST || '0.0.0.0';
    
    server.listen(PORT, HOST, () => {
        console.log('🚀 =====================================');
        console.log('🎙️  SONRIX VOICE CHAT SERVER');
        console.log('🚀 =====================================');
        console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log(`🖥️  System: Ubuntu 22.04.5 LTS (Jammy)`);
        console.log(`⚡ Node.js: ${process.version}`);
        console.log(`🗄️  MySQL: 8.0.42 (Ubuntu)`);
        console.log(`🌐 Nginx: 1.18.0 Ready`);
        console.log('🚀 =====================================');
        console.log(`📱 Local: http://localhost:${PORT}`);
        console.log(`🌐 Network: http://[your-ip]:${PORT}`);
        console.log(`👨‍💼 Admin Panel: http://[your-ip]:${PORT}/admin`);
        console.log(`💊 Health Check: http://[your-ip]:${PORT}/health`);
        console.log('🚀 =====================================');
        console.log(`🔐 Security: Helmet + Rate Limiting + JWT`);
        console.log(`📊 Features: WebRTC + Admin Panel + Database`);
        console.log(`🗄️  Database: ${dbConfig.database}@${dbConfig.host}`);
        console.log('🚀 =====================================');
        console.log('✅ Server is ready for connections!');
    });
}).catch((error) => {
    console.error('💀 Failed to start server:', error);
    process.exit(1);
});❌ Database connection error:', err);
            if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
                console.log('🔄 Attempting to reconnect to database...');
                await initDatabase();
            }
        });
        
        // Start cleanup interval
        setInterval(cleanupExpiredMessages, 24 * 60 * 60 * 1000); // Daily cleanup
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        console.log('💡 Database configuration:', {
            host: dbConfig.host,
            user: dbConfig.user,
            database: dbConfig.database,
            socket: dbConfig.socketPath
        });
        
        if (retries > 0) {
            console.log(`🔄 Retrying connection in 5 seconds... (${retries} attempts left)`);
            setTimeout(() => initDatabase(retries - 1), 5000);
        } else {
            console.error('💀 Failed to connect to database after multiple attempts');
            process.exit(1);
        }
    }
}

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const token = req.session.token;
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied - Authentication required' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [rows] = await db.execute('SELECT * FROM users WHERE id = ? AND is_active = true', [decoded.userId]);
        
        if (rows.length === 0) {
            req.session.destroy();
            return res.status(401).json({ error: 'User not found or account disabled' });
        }
        
        req.user = rows[0];
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        req.session.destroy();
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Administrator access required' });
    }
    next();
};

// Health check endpoint
app.get('/health', async (req, res) => {
    try {
        await db.execute('SELECT 1');
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            version: '1.0.0',
            database: 'connected',
            uptime: process.uptime()
        });
    } catch (error) {
        res.status(503).json({
            status: 'unhealthy',
            error: 'Database connection failed'
        });
    }
});

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
        role: req.user.role,
        email: req.user.email,
        lastLogin: req.user.last_login
    });
});

app.get('/api/auth-token', authenticateToken, (req, res) => {
    res.json({ token: req.session.token });
});

// Authentication routes with enhanced security
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        // Rate limiting for login attempts
        const clientIP = req.ip;
        console.log(`🔑 Login attempt from ${clientIP} for user: ${username}`);
        
        const [rows] = await db.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = true', 
            [username]
        );
        
        if (rows.length === 0) {
            console.log(`❌ Login failed: User not found - ${username}`);
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            console.log(`❌ Login failed: Invalid password - ${username}`);
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        // Update last login timestamp
        await db.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
        req.session.token = token;
        
        console.log(`✅ Login successful: ${user.username} (${user.role}) from ${clientIP}`);
        
        res.json({ 
            success: true, 
            user: { 
                id: user.id, 
                username: user.username, 
                role: user.role,
                email: user.email
            } 
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during authentication' });
    }
});

app.post('/api/logout', (req, res) => {
    const username = req.user?.username || 'Unknown';
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
        } else {
            console.log(`✅ User logged out: ${username}`);
        }
    });
    res.json({ success: true });
});

// Admin API routes (enhanced)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT u.id, u.username, u.email, u.role, u.is_active, 
                   u.created_at, u.last_login,
                   creator.username as created_by_name
            FROM users u
            LEFT JOIN users creator ON u.created_by = creator.id
            ORDER BY u.created_at DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        if (username.length < 3 || password.length < 6) {
            return res.status(400).json({ error: 'Username must be at least 3 characters, password at least 6 characters' });
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
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.put('/api/admin/users/:id/toggle', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        // Don't allow disabling admin users
        const [user] = await db.execute('SELECT role, username FROM users WHERE id = ?', [userId]);
        if (user[0]?.role === 'admin') {
            return res.status(400).json({ error: 'Cannot disable administrator accounts' });
        }
        
        await db.execute('UPDATE users SET is_active = NOT is_active WHERE id = ?', [userId]);
        console.log(`✅ User status toggled: ${user[0]?.username} by ${req.user.username}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Toggle user error:', error);
        res.status(500).json({ error: 'Failed to update user status' });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        // Don't allow deleting admin users
        const [user] = await db.execute('SELECT role, username FROM users WHERE id = ?', [userId]);
        if (user[0]?.role === 'admin') {
            return res.status(400).json({ error: 'Cannot delete administrator accounts' });
        }
        
        await db.execute('DELETE FROM users WHERE id = ?', [userId]);
        console.log(`✅ User deleted: ${user[0]?.username} by ${req.user.username}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.get('/api/admin/rooms', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT r.*, u.username as created_by_name,
                   (SELECT COUNT(*) FROM user_sessions s 
                    WHERE s.room_id = r.id AND s.left_at IS NULL) as active_users,
                   (SELECT COUNT(*) FROM messages m 
                    WHERE m.room_id = r.id) as total_messages
            FROM rooms r
            LEFT JOIN users u ON r.created_by = u.id
            ORDER BY r.created_at DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Get rooms error:', error);
        res.status(500).json({ error: 'Database query failed' });
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
            LIMIT 200
        `);
        res.json(rows);
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ error: 'Database query failed' });
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
        
        const [activeConnections] = await db.execute(`
            SELECT COUNT(*) as active 
            FROM user_sessions WHERE left_at IS NULL
        `);
        
        res.json({
            totalUsers: userStats[0].total || 0,
            activeUsers: userStats[0].active || 0,
            totalRooms: roomStats[0].total || 0,
            todayMessages: messageStats[0].today || 0,
            totalMessages: totalMessages[0].total || 0,
            activeConnections: activeConnections[0].active || 0
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// WebRTC Socket.io with enhanced authentication
io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication required'));
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const [rows] = await db.execute('SELECT * FROM users WHERE id = ? AND is_active = true', [decoded.userId]);
        
        if (rows.length === 0) {
            return next(new Error('User not found or account disabled'));
        }
        
        socket.user = rows[0];
        next();
    } catch (error) {
        console.error('Socket authentication error:', error);
        next(new Error('Authentication failed'));
    }
});

// Active rooms tracking
const activeRooms = new Map();

io.on('connection', (socket) => {
    console.log(`✅ WebRTC connection: ${socket.user.username} (${socket.id}) [${socket.user.role}]`);

    socket.on('join-room', async (data) => {
        try {
            const { roomCode } = data;
            
            if (!roomCode || roomCode.length > 20 || !/^[A-Z0-9]+$/.test(roomCode)) {
                socket.emit('error', { message: 'Invalid room code format' });
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
        console.log(`📞 WebRTC Offer: ${socket.user.username} -> target`);
    });

    socket.on('answer', (data) => {
        socket.to(data.target).emit('answer', {
            answer: data.answer,
            sender: socket.id
        });
        console.log(`📞 WebRTC Answer: ${socket.user.username} -> target`);
    });

    socket.on('ice-candidate', (data) => {
        socket.to(data.target).emit('ice-candidate', {
            candidate: data.candidate,
            sender: socket.id
        });
    });

    // Media controls with enhanced logging
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
                
                console.log(`🎤 ${socket.user.username} mic: ${isMicOn ? 'ON' : 'OFF'} in ${roomCode}`);
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
                
                console.log(`📹 ${socket.user.username} video: ${isVideoOn ? 'ON' : 'OFF'} in ${roomCode}`);
            }
        }
    });

    socket.on('disconnect', async () => {
        console.log(`❌ WebRTC disconnection: ${socket.user.username} (${socket.id})`);
        
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
        console.error('
