require('dotenv').config();

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: process.env.NODE_ENV === 'production' ? process.env.DOMAIN : "*",
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
            styleSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "ws:", "wss:"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "cdnjs.cloudflare.com"]
        }
    }
}));

app.use(compression());
app.use(cors({
    origin: process.env.CORS_ORIGIN || true,
    credentials: true
}));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
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
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        httpOnly: true
    }
}));

// Static files
app.use(express.static('public', {
    maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0
}));

// Database Configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'sonrix_user',
    password: process.env.DB_PASSWORD || 'Sonrix2024_App_DB_Pass!',
    database: process.env.DB_NAME || 'sonrix_voice',
    charset: 'utf8mb4',
    connectionLimit: 10,
    acquireTimeout: 60000,
    timeout: 60000,
    reconnect: true
};

let db;

// Database connection with retry logic
async function initDatabase(retries = 5) {
    try {
        console.log('🔄 Connecting to MySQL...');
        db = await mysql.createConnection(dbConfig);
        
        await db.execute('SELECT 1 as test');
        console.log('✅ MySQL connection established successfully');
        
        // Setup error handling
        db.on('error', async (err) => {
            console.error('❌ Database connection error:', err);
            if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
                console.log('🔄 Attempting to reconnect...');
                await initDatabase();
            }
        });
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        
        if (retries > 0) {
            console.log(`🔄 Retrying in 5 seconds... (${retries} attempts left)`);
            setTimeout(() => initDatabase(retries - 1), 5000);
        } else {
            console.error('💀 Failed to connect to database after multiple attempts');
            process.exit(1);
        }
    }
}

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const token = req.session.token || req.headers.authorization?.split(' ')[1];
    
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
            version: '2.0.0',
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
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/admin', authenticateToken, requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/voice-chat', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'voice-chat.html'));
});

// API Routes
app.get('/api/user-info', authenticateToken, (req, res) => {
    res.json({
        id: req.user.id,
        username: req.user.username,
        role: req.user.role,
        email: req.user.email,
        lastLogin: req.user.last_login
    });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        console.log(`🔑 Login attempt for user: ${username}`);
        
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
        
        // Update last login
        await db.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
        req.session.token = token;
        
        console.log(`✅ Login successful: ${user.username} (${user.role})`);
        
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

// Logout endpoint
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

// Admin API Routes
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
        
        const [activeConnections] = await db.execute(`
            SELECT COUNT(*) as active 
            FROM user_sessions WHERE left_at IS NULL
        `);
        
        res.json({
            totalUsers: userStats[0].total || 0,
            activeUsers: userStats[0].active || 0,
            totalRooms: roomStats[0].total || 0,
            todayMessages: messageStats[0].today || 0,
            activeConnections: activeConnections[0].active || 0
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT u.id, u.username, u.email, u.role, u.is_active, 
                   u.created_at, u.last_login
            FROM users u
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

// WebRTC Socket.io with authentication
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

// Active rooms and users tracking
const activeRooms = new Map();
const activeUsers = new Map();

io.on('connection', (socket) => {
    console.log(`✅ User connected: ${socket.user.username} (${socket.id})`);
    
    // Add to active users
    activeUsers.set(socket.id, {
        id: socket.user.id,
        username: socket.user.username,
        role: socket.user.role,
        socketId: socket.id,
        currentRoom: null,
        joinedAt: new Date()
    });

    // Authentication event
    socket.on('authenticate', (data) => {
        socket.emit('authenticated', { 
            success: true, 
            user: socket.user 
        });
    });

    // Get rooms list
    socket.on('get-rooms', async () => {
        try {
            const [rooms] = await db.execute(`
                SELECT r.*, u.username as creator,
                       (SELECT COUNT(*) FROM user_sessions s 
                        WHERE s.room_id = r.id AND s.left_at IS NULL) as current_users
                FROM rooms r
                LEFT JOIN users u ON r.created_by = u.id
                ORDER BY r.created_at DESC
            `);
            
            const roomsWithStatus = rooms.map(room => ({
                ...room,
                has_password: !!room.password,
                password: undefined // Don't send password to client
            }));
            
            socket.emit('rooms-list', roomsWithStatus);
        } catch (error) {
            console.error('Get rooms error:', error);
            socket.emit('error', { message: 'Failed to load rooms' });
        }
    });

    // Get users list
    socket.on('get-users', () => {
        const users = Array.from(activeUsers.values()).map(user => ({
            id: user.id,
            username: user.username,
            status: user.currentRoom ? 'in-room' : 'online',
            room: user.currentRoom
        }));
        
        socket.emit('users-list', users);
        io.emit('users-list', users); // Broadcast to all
    });

    // Create room
    socket.on('create-room', async (data) => {
        try {
            const { name, password, isPrivate, maxUsers } = data;
            
            if (!name || name.length < 3 || name.length > 50) {
                socket.emit('room-creation-failed', { message: 'Room name must be 3-50 characters' });
                return;
            }
            
            // Generate unique room code
            const roomCode = Math.random().toString(36).substring(2, 8).toUpperCase();
            
            const hashedPassword = password ? await bcrypt.hash(password, 10) : null;
            
            const [result] = await db.execute(`
                INSERT INTO rooms (room_code, room_name, created_by, is_private, password, max_users) 
                VALUES (?, ?, ?, ?, ?, ?)
            `, [roomCode, name, socket.user.id, isPrivate || false, hashedPassword, maxUsers || 10]);
            
            const room = {
                id: result.insertId,
                room_code: roomCode,
                room_name: name,
                created_by: socket.user.id,
                is_private: isPrivate || false,
                max_users: maxUsers || 10
            };
            
            console.log(`🏠 Room created: ${roomCode} by ${socket.user.username}`);
            socket.emit('room-created', room);
            
            // Broadcast updated room list
            socket.broadcast.emit('rooms-list-updated');
            
        } catch (error) {
            console.error('Create room error:', error);
            socket.emit('room-creation-failed', { message: 'Failed to create room' });
        }
    });

    // Join room
    socket.on('join-room', async (data) => {
        try {
            const { roomId, password } = data;
            
            // Get room info
            const [rooms] = await db.execute('SELECT * FROM rooms WHERE id = ? OR room_code = ?', [roomId, roomId]);
            
            if (rooms.length === 0) {
                socket.emit('join-room-failed', { message: 'Room not found' });
                return;
            }
            
            const room = rooms[0];
            
            // Check password if required
            if (room.password) {
                if (!password) {
                    socket.emit('room-password-required', { roomId: room.id });
                    return;
                }
                
                const validPassword = await bcrypt.compare(password, room.password);
                if (!validPassword) {
                    socket.emit('join-room-failed', { message: 'Invalid room password' });
                    return;
                }
            }
            
            // Check room capacity
            const roomSize = activeRooms.get(room.room_code)?.size || 0;
            if (roomSize >= room.max_users) {
                socket.emit('join-room-failed', { message: 'Room is full' });
                return;
            }
            
            // Leave current room if any
            if (socket.currentRoom) {
                socket.leave(socket.currentRoom.room_code);
                await leaveCurrentRoom(socket);
            }
            
            // Join new room
            socket.join(room.room_code);
            socket.currentRoom = room;
            
            // Update active rooms
            if (!activeRooms.has(room.room_code)) {
                activeRooms.set(room.room_code, new Map());
            }
            
            const roomUsers = activeRooms.get(room.room_code);
            roomUsers.set(socket.id, {
                id: socket.user.id,
                username: socket.user.username,
                role: socket.user.role,
                socketId: socket.id,
                isMuted: false,
                isVideoOn: false
            });
            
            // Update active users
            const activeUser = activeUsers.get(socket.id);
            if (activeUser) {
                activeUser.currentRoom = room.room_code;
            }
            
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
            
            // Get current participants
            const participants = Array.from(roomUsers.values());
            
            // Notify user of successful join
            socket.emit('joined-room', {
                room: room,
                participants: participants
            });
            
            // Notify others in room
            socket.to(room.room_code).emit('user-joined', {
                id: socket.user.id,
                username: socket.user.username,
                role: socket.user.role,
                socketId: socket.id
            });
            
            // Log join message
            await logMessage(room.id, socket.user.id, 'system', 
                `${socket.user.username} odaya katıldı`);
            
            console.log(`👤 ${socket.user.username} joined room ${room.room_code} (${roomUsers.size} users total)`);
            
        } catch (error) {
            console.error('Join room error:', error);
            socket.emit('join-room-failed', { message: 'Failed to join room' });
        }
    });

    // Leave room
    socket.on('leave-room', async (data) => {
        await leaveCurrentRoom(socket);
    });

    // WebRTC signaling
    socket.on('webrtc-offer', (data) => {
        socket.to(data.targetUserId).emit('webrtc-offer', {
            offer: data.offer,
            fromUserId: socket.id,
            roomId: data.roomId
        });
    });

    socket.on('webrtc-answer', (data) => {
        socket.to(data.targetUserId).emit('webrtc-answer', {
            answer: data.answer,
            fromUserId: socket.id,
            roomId: data.roomId
        });
    });

    socket.on('webrtc-ice-candidate', (data) => {
        socket.to(data.targetUserId).emit('webrtc-ice-candidate', {
            candidate: data.candidate,
            fromUserId: socket.id,
            roomId: data.roomId
        });
    });

    // Media controls
    socket.on('user-muted', async (data) => {
        if (socket.currentRoom) {
            const roomCode = socket.currentRoom.room_code;
            const roomUsers = activeRooms.get(roomCode);
            
            if (roomUsers && roomUsers.has(socket.id)) {
                roomUsers.get(socket.id).isMuted = data.isMuted;
                socket.to(roomCode).emit('user-muted', {
                    userId: socket.id,
                    isMuted: data.isMuted
                });
            }
        }
    });

    socket.on('user-speaking', (data) => {
        if (socket.currentRoom) {
            socket.to(socket.currentRoom.room_code).emit('user-speaking', {
                userId: socket.id,
                isSpeaking: data.isSpeaking
            });
        }
    });

    // Disconnect handler
    socket.on('disconnect', async () => {
        console.log(`❌ User disconnected: ${socket.user.username} (${socket.id})`);
        
        // Leave current room
        await leaveCurrentRoom(socket);
        
        // Remove from active users
        activeUsers.delete(socket.id);
        
        // Broadcast updated user list
        const users = Array.from(activeUsers.values()).map(user => ({
            id: user.id,
            username: user.username,
            status: user.currentRoom ? 'in-room' : 'online',
            room: user.currentRoom
        }));
        io.emit('users-list', users);
    });
});

// Helper function to leave current room
async function leaveCurrentRoom(socket) {
    if (!socket.currentRoom) return;
    
    const roomCode = socket.currentRoom.room_code;
    const roomUsers = activeRooms.get(roomCode);
    
    if (roomUsers) {
        roomUsers.delete(socket.id);
        
        // If room is empty, remove it
        if (roomUsers.size === 0) {
            activeRooms.delete(roomCode);
            console.log(`🏠 Room ${roomCode} is now empty`);
        } else {
            // Notify others in room
            socket.to(roomCode).emit('user-left', {
                id: socket.user.id,
                username: socket.user.username,
                socketId: socket.id
            });
        }
    }
    
    // Update session end time
    if (socket.sessionId) {
        await db.execute(`
            UPDATE user_sessions 
            SET left_at = NOW(), 
                duration_minutes = TIMESTAMPDIFF(MINUTE, joined_at, NOW()) 
            WHERE id = ?
        `, [socket.sessionId]);
    }
    
    // Log leave message
    if (socket.currentRoom) {
        await logMessage(socket.currentRoom.id, socket.user.id, 'system', 
            `${socket.user.username} odadan ayrıldı`);
    }
    
    // Update active user
    const activeUser = activeUsers.get(socket.id);
    if (activeUser) {
        activeUser.currentRoom = null;
    }
    
    socket.leave(roomCode);
    socket.currentRoom = null;
    socket.sessionId = null;
}

// Helper function to log messages
async function logMessage(roomId, userId, messageType, content, metadata = null) {
    try {
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

// Cleanup function
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

// Start cleanup interval
setInterval(cleanupExpiredMessages, 24 * 60 * 60 * 1000); // Daily cleanup

// Initialize database and start server
initDatabase().then(() => {
    const PORT = process.env.PORT || 3000;
    const HOST = process.env.HOST || '0.0.0.0';
    
    server.listen(PORT, HOST, () => {
        console.log('🚀 =====================================');
        console.log('🎙️  SONRIX VOICE CHAT SERVER');
        console.log('🚀 =====================================');
        console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log(`🖥️  System: Ubuntu 22.04 LTS`);
        console.log(`⚡ Node.js: ${process.version}`);
        console.log(`🗄️  MySQL: Connected`);
        console.log('🚀 =====================================');
        console.log(`📱 Local: http://localhost:${PORT}`);
        console.log(`🌐 Network: http://[your-ip]:${PORT}`);
        console.log(`👨‍💼 Admin Panel: http://[your-ip]:${PORT}/admin`);
        console.log(`💊 Health Check: http://[your-ip]:${PORT}/health`);
        console.log('🚀 =====================================');
        console.log(`🔐 Security: Helmet + Rate Limiting + JWT`);
        console.log(`📊 Features: WebRTC + Admin Panel + Database`);
        console.log('🚀 =====================================');
        console.log('✅ Server is ready for connections!');
    });
}).catch((error) => {
    console.error('💀 Failed to start server:', error);
    process.exit(1);
});
