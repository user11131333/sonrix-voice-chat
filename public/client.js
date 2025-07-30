/**
 * Sonrix Voice - WebRTC Client
 * Ubuntu 22.04 + MySQL 8.0 optimized version
 */

class SonrixVoiceClient {
    constructor() {
        this.socket = null;
        this.localStream = null;
        this.peerConnections = new Map();
        this.currentRoom = null;
        this.currentUser = null;
        this.isConnected = false;
        this.audioContext = null;
        this.audioAnalyser = null;
        this.mediaConstraints = {
            audio: {
                echoCancellation: true,
                noiseSuppression: true,
                autoGainControl: true,
                sampleRate: 44100,
                channelCount: 1
            },
            video: false
        };
        
        // WebRTC configuration
        this.rtcConfiguration = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' },
                { urls: 'stun:stun2.l.google.com:19302' },
                { urls: 'stun:stun3.l.google.com:19302' }
            ],
            iceCandidatePoolSize: 10
        };
        
        // Audio settings
        this.audioSettings = {
            quality: 'medium',
            volume: 0.5,
            isMuted: false,
            isDeafened: false
        };
        
        // Event handlers
        this.eventHandlers = {
            'connect': this.onConnect.bind(this),
            'disconnect': this.onDisconnect.bind(this),
            'authenticated': this.onAuthenticated.bind(this),
            'authentication-failed': this.onAuthenticationFailed.bind(this),
            'rooms-list': this.onRoomsList.bind(this),
            'users-list': this.onUsersList.bind(this),
            'room-created': this.onRoomCreated.bind(this),
            'room-creation-failed': this.onRoomCreationFailed.bind(this),
            'joined-room': this.onJoinedRoom.bind(this),
            'join-room-failed': this.onJoinRoomFailed.bind(this),
            'user-joined': this.onUserJoined.bind(this),
            'user-left': this.onUserLeft.bind(this),
            'room-password-required': this.onRoomPasswordRequired.bind(this),
            'webrtc-offer': this.onWebRTCOffer.bind(this),
            'webrtc-answer': this.onWebRTCAnswer.bind(this),
            'webrtc-ice-candidate': this.onWebRTCIceCandidate.bind(this),
            'user-muted': this.onUserMuted.bind(this),
            'user-speaking': this.onUserSpeaking.bind(this),
            'room-settings-updated': this.onRoomSettingsUpdated.bind(this),
            'error': this.onError.bind(this)
        };
        
        this.init();
    }
    
    /**
     * Initialize the client
     */
    async init() {
        try {
            console.log('🎤 Sonrix Voice Client initializing...');
            
            // Check authentication
            if (!this.checkAuth()) {
                console.log('❌ Authentication failed, redirecting to login');
                return;
            }
            
            // Initialize audio
            await this.initAudio();
            
            // Initialize socket connection
            this.initSocket();
            
            // Setup UI event listeners
            this.setupUIEventListeners();
            
            console.log('✅ Sonrix Voice Client initialized successfully');
        } catch (error) {
            console.error('❌ Failed to initialize client:', error);
            this.showNotification('Uygulama başlatılamadı: ' + error.message, 'error');
        }
    }
    
    /**
     * Check user authentication
     */
    checkAuth() {
        const token = localStorage.getItem('authToken');
        const userData = localStorage.getItem('userData');
        
        if (!token || !userData) {
            window.location.href = '/login.html';
            return false;
        }
        
        try {
            this.currentUser = JSON.parse(userData);
            return true;
        } catch (error) {
            console.error('Invalid user data:', error);
            localStorage.removeItem('authToken');
            localStorage.removeItem('userData');
            window.location.href = '/login.html';
            return false;
        }
    }
    
    /**
     * Initialize audio system
     */
    async initAudio() {
        try {
            console.log('🎵 Initializing audio system...');
            
            // Request microphone access
            this.localStream = await navigator.mediaDevices.getUserMedia(this.mediaConstraints);
            
            // Create audio context for analysis
            this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            this.audioAnalyser = this.audioContext.createAnalyser();
            this.audioAnalyser.fftSize = 256;
            
            const source = this.audioContext.createMediaStreamSource(this.localStream);
            source.connect(this.audioAnalyser);
            
            // Start voice activity detection
            this.startVoiceActivityDetection();
            
            console.log('✅ Audio system initialized');
        } catch (error) {
            console.error('❌ Audio initialization failed:', error);
            this.showNotification('Mikrofon erişimi reddedildi. Sesli sohbet için mikrofon gereklidir.', 'error');
            throw error;
        }
    }
    
    /**
     * Initialize Socket.IO connection
     */
    initSocket() {
        console.log('🔌 Connecting to server...');
        
        this.socket = io({
            transports: ['websocket', 'polling'],
            timeout: 10000,
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionAttempts: 5
        });
        
        // Register event handlers
        Object.entries(this.eventHandlers).forEach(([event, handler]) => {
            this.socket.on(event, handler);
        });
    }
    
    /**
     * Setup UI event listeners
     */
    setupUIEventListeners() {
        // Room creation form
        const createRoomForm = document.getElementById('createRoomForm');
        if (createRoomForm) {
            createRoomForm.addEventListener('submit', this.handleCreateRoom.bind(this));
        }
        
        // Password form
        const passwordForm = document.getElementById('passwordForm');
        if (passwordForm) {
            passwordForm.addEventListener('submit', this.handlePasswordSubmit.bind(this));
        }
        
        // Volume control
        const volumeSlider = document.getElementById('volumeSlider');
        if (volumeSlider) {
            volumeSlider.addEventListener('input', this.handleVolumeChange.bind(this));
        }
        
        // Audio quality selector
        const audioQuality = document.getElementById('audioQuality');
        if (audioQuality) {
            audioQuality.addEventListener('change', this.handleAudioQualityChange.bind(this));
        }
        
        // Window events
        window.addEventListener('beforeunload', this.handleBeforeUnload.bind(this));
        window.addEventListener('resize', this.handleResize.bind(this));
    }
    
    // Socket Event Handlers
    
    onConnect() {
        console.log('✅ Connected to server');
        this.isConnected = true;
        
        // Authenticate with server
        this.socket.emit('authenticate', {
            token: localStorage.getItem('authToken'),
            userData: this.currentUser
        });
    }
    
    onDisconnect(reason) {
        console.log('❌ Disconnected from server:', reason);
        this.isConnected = false;
        
        // Close all peer connections
        this.peerConnections.forEach(pc => pc.close());
        this.peerConnections.clear();
        
        this.showNotification('Sunucu bağlantısı kesildi: ' + reason, 'warning');
        
        // Attempt to reconnect
        if (reason !== 'io client disconnect') {
            setTimeout(() => {
                if (!this.isConnected) {
                    this.socket.connect();
                }
            }, 2000);
        }
    }
    
    onAuthenticated(data) {
        console.log('✅ Authenticated:', data);
        
        // Update UI with user info
        const usernameEl = document.getElementById('currentUsername');
        if (usernameEl) {
            usernameEl.textContent = this.currentUser.username;
        }
        
        // Load initial data
        this.loadRooms();
        this.loadUsers();
        
        this.showNotification('Sonrix Voice\'a hoş geldiniz!', 'success');
    }
    
    onAuthenticationFailed(error) {
        console.error('❌ Authentication failed:', error);
        this.showNotification('Kimlik doğrulama başarısız: ' + error.message, 'error');
        
        // Clear stored credentials
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
        
        // Redirect to login
        setTimeout(() => {
            window.location.href = '/login.html';
        }, 2000);
    }
    
    onRoomsList(rooms) {
        console.log('📋 Received rooms list:', rooms);
        this.updateRoomsList(rooms);
    }
    
    onUsersList(users) {
        console.log('👥 Received users list:', users);
        this.updateUsersList(users);
    }
    
    onRoomCreated(room) {
        console.log('✅ Room created:', room);
        this.showNotification(`Oda "${room.name}" başarıyla oluşturuldu`, 'success');
        this.loadRooms();
        
        // Clear form
        const form = document.getElementById('createRoomForm');
        if (form) form.reset();
    }
    
    onRoomCreationFailed(error) {
        console.error('❌ Room creation failed:', error);
        this.showNotification('Oda oluşturulamadı: ' + error.message, 'error');
    }
    
    onJoinedRoom(data) {
        console.log('✅ Joined room:', data);
        this.currentRoom = data.room;
        
        // Update UI
        this.showRoomContent(data);
        
        // Create peer connections for existing participants
        data.participants.forEach(user => {
            if (user.id !== this.currentUser.id) {
                this.createPeerConnection(user.id, true); // initiator
            }
        });
        
        this.showNotification(`"${data.room.name}" odasına katıldınız`, 'success');
    }
    
    onJoinRoomFailed(error) {
        console.error('❌ Join room failed:', error);
        this.showNotification('Odaya katılamadı: ' + error.message, 'error');
    }
    
    onUserJoined(user) {
        console.log('👤 User joined:', user);
        
        if (this.currentRoom) {
            this.addParticipant(user);
            this.createPeerConnection(user.id, false); // not initiator
        }
        
        this.showNotification(`${user.username} odaya katıldı`, 'info');
    }
    
    onUserLeft(user) {
        console.log('👤 User left:', user);
        
        if (this.currentRoom) {
            this.removeParticipant(user);
        }
        
        // Close peer connection
        const pc = this.peerConnections.get(user.id);
        if (pc) {
            pc.close();
            this.peerConnections.delete(user.id);
        }
        
        this.showNotification(`${user.username} odadan ayrıldı`, 'info');
    }
    
    onRoomPasswordRequired(data) {
        console.log('🔒 Room password required:', data);
        this.showPasswordModal(data.roomId);
    }
    
    async onWebRTCOffer(data) {
        console.log('📞 Received WebRTC offer from:', data.fromUserId);
        
        try {
            const pc = this.createPeerConnection(data.fromUserId, false);
            await pc.setRemoteDescription(data.offer);
            
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            
            this.socket.emit('webrtc-answer', {
                answer: answer,
                targetUserId: data.fromUserId,
                roomId: this.currentRoom.id
            });
        } catch (error) {
            console.error('❌ Error handling WebRTC offer:', error);
        }
    }
    
    async onWebRTCAnswer(data) {
        console.log('📞 Received WebRTC answer from:', data.fromUserId);
        
        try {
            const pc = this.peerConnections.get(data.fromUserId);
            if (pc) {
                await pc.setRemoteDescription(data.answer);
            }
        } catch (error) {
            console.error('❌ Error handling WebRTC answer:', error);
        }
    }
    
    async onWebRTCIceCandidate(data) {
        console.log('🧊 Received ICE candidate from:', data.fromUserId);
        
        try {
            const pc = this.peerConnections.get(data.fromUserId);
            if (pc) {
                await pc.addIceCandidate(data.candidate);
            }
        } catch (error) {
            console.error('❌ Error handling ICE candidate:', error);
        }
    }
    
    onUserMuted(data) {
        console.log('🔇 User muted status changed:', data);
        this.updateParticipantMuteStatus(data.userId, data.isMuted);
    }
    
    onUserSpeaking(data) {
        console.log('🗣️ User speaking:', data);
        this.updateParticipantSpeakingStatus(data.userId, data.isSpeaking);
    }
    
    onRoomSettingsUpdated(settings) {
        console.log('⚙️ Room settings updated:', settings);
        this.showNotification('Oda ayarları güncellendi', 'info');
    }
    
    onError(error) {
        console.error('❌ Server error:', error);
        this.showNotification('Sunucu hatası: ' + error.message, 'error');
    }
    
    // WebRTC Methods
    
    /**
     * Create a peer connection
     */
    createPeerConnection(userId, isInitiator = false) {
        console.log(`🔗 Creating peer connection with ${userId} (initiator: ${isInitiator})`);
        
        const pc = new RTCPeerConnection(this.rtcConfiguration);
        
        // Add local stream
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => {
                pc.addTrack(track, this.localStream);
            });
        }
        
        // Handle remote stream
        pc.ontrack = (event) => {
            console.log('🎵 Received remote stream from:', userId);
            const audio = document.getElementById(`audio-${userId}`);
            if (audio) {
                audio.srcObject = event.streams[0];
                audio.volume = this.audioSettings.volume;
                audio.muted = this.audioSettings.isDeafened;
            }
        };
        
        // Handle ICE candidates
        pc.onicecandidate = (event) => {
            if (event.candidate) {
                this.socket.emit('webrtc-ice-candidate', {
                    candidate: event.candidate,
                    targetUserId: userId,
                    roomId: this.currentRoom.id
                });
            }
        };
        
        // Handle connection state changes
        pc.onconnectionstatechange = () => {
            console.log(`🔗 Connection state with ${userId}:`, pc.connectionState);
            
            if (pc.connectionState === 'connected') {
                this.updateParticipantConnectionStatus(userId, 'connected');
            } else if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
                this.updateParticipantConnectionStatus(userId, 'disconnected');
            }
        };
        
        // Store peer connection
        this.peerConnections.set(userId, pc);
        
        // Create offer if initiator
        if (isInitiator) {
            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .then(() => {
                    this.socket.emit('webrtc-offer', {
                        offer: pc.localDescription,
                        targetUserId: userId,
                        roomId: this.currentRoom.id
                    });
                })
                .catch(error => {
                    console.error('❌ Error creating offer:', error);
                });
        }
        
        return pc;
    }
    
    // Voice Activity Detection
    
    /**
     * Start voice activity detection
     */
    startVoiceActivityDetection() {
        if (!this.audioAnalyser) return;
        
        const dataArray = new Uint8Array(this.audioAnalyser.frequencyBinCount);
        let isSpeaking = false;
        let speakingTimeout = null;
        
        const detectVoice = () => {
            this.audioAnalyser.getByteFrequencyData(dataArray);
            
            // Calculate volume level
            const volume = dataArray.reduce((sum, value) => sum + value, 0) / dataArray.length;
            const threshold = 30; // Adjust sensitivity
            
            if (volume > threshold && !this.audioSettings.isMuted) {
                if (!isSpeaking) {
                    isSpeaking = true;
                    this.onStartSpeaking();
                }
                
                // Clear existing timeout
                if (speakingTimeout) {
                    clearTimeout(speakingTimeout);
                }
                
                // Set timeout to stop speaking detection
                speakingTimeout = setTimeout(() => {
                    isSpeaking = false;
                    this.onStopSpeaking();
                }, 500);
            }
            
            requestAnimationFrame(detectVoice);
        };
        
        detectVoice();
    }
    
    onStartSpeaking() {
        console.log('🗣️ Started speaking');
        if (this.currentRoom) {
            this.socket.emit('user-speaking', {
                roomId: this.currentRoom.id,
                isSpeaking: true
            });
        }
    }
    
    onStopSpeaking() {
        console.log('🤐 Stopped speaking');
        if (this.currentRoom) {
            this.socket.emit('user-speaking', {
                roomId: this.currentRoom.id,
                isSpeaking: false
            });
        }
    }
    
    // UI Methods
    
    /**
     * Load rooms from server
     */
    loadRooms() {
        if (this.socket && this.isConnected) {
            this.socket.emit('get-rooms');
        }
    }
    
    /**
     * Load users from server
     */
    loadUsers() {
        if (this.socket && this.isConnected) {
            this.socket.emit('get-users');
        }
    }
    
    /**
     * Update rooms list in UI
     */
    updateRoomsList(rooms) {
        const container = document.getElementById('roomsList');
        if (!container) return;
        
        if (!rooms || rooms.length === 0) {
            container.innerHTML = '<div class="no-rooms">Henüz aktif oda yok</div>';
            return;
        }
        
        container.innerHTML = rooms.map(room => `
            <div class="room-item" onclick="window.sonrixClient.joinRoom('${room.id}')">
                <div class="room-header">
                    <span class="room-name">${this.escapeHtml(room.name)}</span>
                    ${room.has_password ? '<i class="fas fa-lock" title="Şifreli"></i>' : ''}
                    ${room.is_private ? '<i class="fas fa-eye-slash" title="Özel"></i>' : ''}
                </div>
                <div class="room-info">
                    <span class="room-users">
                        <i class="fas fa-users"></i> ${room.current_users}/${room.max_users}
                    </span>
                    <span class="room-creator">@${this.escapeHtml(room.creator)}</span>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Update users list in UI
     */
    updateUsersList(users) {
        const container = document.getElementById('usersList');
        const count = document.getElementById('onlineCount');
        
        if (!container || !count) return;
        
        count.textContent = users.length;
        
        if (!users || users.length === 0) {
            container.innerHTML = '<div class="no-users">Çevrimiçi kullanıcı yok</div>';
            return;
        }
        
        container.innerHTML = users.map(user => `
            <div class="user-item">
                <div class="user-avatar">
                    <i class="fas fa-user"></i>
                </div>
                <div class="user-info">
                    <span class="user-name">${this.escapeHtml(user.username)}</span>
                    <span class="user-status ${user.status}">${this.escapeHtml(user.room || 'Lobby')}</span>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Show room content
     */
    showRoomContent(data) {
        // Hide welcome screen
        const welcomeScreen = document.getElementById('welcomeScreen');
        if (welcomeScreen) {
            welcomeScreen.style.display = 'none';
        }
        
        // Show room content
        const roomContent = document.getElementById('roomContent');
        if (roomContent) {
            roomContent.style.display = 'block';
        }
        
        // Update room info
        const roomName = document.getElementById('currentRoomName');
        if (roomName) {
            roomName.textContent = data.room.name;
        }
        
        // Clear and populate participants
        const participantsGrid = document.getElementById('participantsGrid');
        if (participantsGrid) {
            participantsGrid.innerHTML = '';
            
            data.participants.forEach(user => {
                if (user.id !== this.currentUser.id) {
                    this.addParticipant(user);
                }
            });
        }
        
        this.updateParticipantCount(data.participants.length);
    }
    
    /**
     * Add participant to UI
     */
    addParticipant(user) {
        const grid = document.getElementById('participantsGrid');
        if (!grid) return;
        
        const participant = document.createElement('div');
        participant.className = 'participant';
        participant.id = `participant-${user.id}`;
        participant.innerHTML = `
            <div class="participant-avatar">
                <i class="fas fa-user"></i>
            </div>
            <div class="participant-info">
                <span class="participant-name">${this.escapeHtml(user.username)}</span>
                <div class="participant-controls">
                    <div class="volume-indicator" id="volume-${user.id}"></div>
                    <i class="fas fa-microphone" id="mic-${user.id}"></i>
                </div>
            </div>
            <audio id="audio-${user.id}" autoplay></audio>
        `;
        
        grid.appendChild(participant);
    }
    
    /**
     * Remove participant from UI
     */
    removeParticipant(user) {
        const participant = document.getElementById(`participant-${user.id}`);
        if (participant) {
            participant.remove();
        }
        
        // Update participant count
        if (this.currentRoom) {
            const currentCount = document.getElementById('participantCount');
            if (currentCount) {
                const count = parseInt(currentCount.textContent) - 1;
                currentCount.textContent = Math.max(0, count);
            }
        }
    }
    
    /**
     * Update participant count
     */
    updateParticipantCount(count) {
        const countEl = document.getElementById('participantCount');
        if (countEl) {
            countEl.textContent = count;
        }
    }
    
    /**
     * Update participant mute status
     */
    updateParticipantMuteStatus(userId, isMuted) {
        const micIcon = document.getElementById(`mic-${userId}`);
        if (micIcon) {
            micIcon.className = isMuted ? 'fas fa-microphone-slash' : 'fas fa-microphone';
            micIcon.style.color = isMuted ? '#f56565' : '#48bb78';
        }
    }
    
    /**
     * Update participant speaking status
     */
    updateParticipantSpeakingStatus(userId, isSpeaking) {
        const volumeIndicator = document.getElementById(`volume-${userId}`);
        if (volumeIndicator) {
            volumeIndicator.classList.toggle('active', isSpeaking);
        }
        
        const participant = document.getElementById(`participant-${userId}`);
        if (participant) {
            participant.classList.toggle('speaking', isSpeaking);
        }
    }
    
    /**
     * Update participant connection status
     */
    updateParticipantConnectionStatus(userId, status) {
        const participant = document.getElementById(`participant-${userId}`);
        if (participant) {
            participant.classList.toggle('connected', status === 'connected');
            participant.classList.toggle('disconnected', status === 'disconnected');
        }
    }
    
    /**
     * Show password modal
     */
    showPasswordModal(roomId) {
        const modal = document.getElementById('passwordModal');
        if (modal) {
            modal.style.display = 'flex';
            modal.dataset.roomId = roomId;
            
            const passwordInput = document.getElementById('modalPassword');
            if (passwordInput) {
                passwordInput.focus();
            }
        }
    }
    
    /**
     * Close password modal
     */
    closePasswordModal() {
        const modal = document.getElementById('passwordModal');
        if (modal) {
            modal.style.display = 'none';
            delete modal.dataset.roomId;
            
            const passwordInput = document.getElementById('modalPassword');
            if (passwordInput) {
                passwordInput.value = '';
            }
        }
    }
    
    /**
     * Show notification
     */
    showNotification(message, type = 'info') {
        const container = document.getElementById('notificationContainer');
        if (!container) return;
        
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        const iconMap = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        
        const icon = iconMap[type] || iconMap.info;
        
        notification.innerHTML = `
            <i class="fas fa-${icon}"></i>
            <span>${this.escapeHtml(message)}</span>
            <button onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        container.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }
    
    // Event Handlers
    
    /**
     * Handle create room form submission
     */
    handleCreateRoom(event) {
        event.preventDefault();
        
        const formData = new FormData(event.target);
        const roomData = {
            name: formData.get('roomName')?.trim(),
            password: formData.get('roomPassword') || null,
            isPrivate: formData.has('isPrivate'),
            maxUsers: parseInt(formData.get('maxUsers')) || 10
        };
        
        // Validation
        if (!roomData.name) {
            this.showNotification('Oda adı gerekli', 'error');
            return;
        }
        
        if (roomData.name.length < 3 || roomData.name.length > 50) {
            this.showNotification('Oda adı 3-50 karakter arasında olmalı', 'error');
            return;
        }
        
        if (roomData.password && roomData.password.length < 4) {
            this.showNotification('Şifre en az 4 karakter olmalı', 'error');
            return;
        }
        
        console.log('🏗️ Creating room:', roomData);
        this.socket.emit('create-room', roomData);
    }
    
    /**
     * Handle password form submission
     */
    handlePasswordSubmit(event) {
        event.preventDefault();
        
        const modal = document.getElementById('passwordModal');
        const roomId = modal?.dataset.roomId;
        const password = document.getElementById('modalPassword')?.value;
        
        if (!roomId || !password) {
            this.showNotification('Geçersiz şifre', 'error');
            return;
        }
        
        this.joinRoom(roomId, password);
        this.closePasswordModal();
    }
    
    /**
     * Handle volume change
     */
    handleVolumeChange(event) {
        const volume = parseFloat(event.target.value) / 100;
        this.audioSettings.volume = volume;
        
        // Update all remote audio elements
        document.querySelectorAll('audio[id^="audio-"]').forEach(audio => {
            audio.volume = volume;
        });
    }
    
    /**
     * Handle audio quality change
     */
    handleAudioQualityChange(event) {
        const quality = event.target.value;
        this.audioSettings.quality = quality;
        
        if (!this.localStream) return;
        
        const constraints = {
            low: { sampleRate: 8000, channelCount: 1, bitrate: 32000 },
            medium: { sampleRate: 22050, channelCount: 1, bitrate: 64000 },
            high: { sampleRate: 44100, channelCount: 2, bitrate: 128000 }
        };
        
        const audioTrack = this.localStream.getAudioTracks()[0];
        if (audioTrack) {
            audioTrack.applyConstraints(constraints[quality])
                .then(() => {
                    console.log('✅ Audio quality updated to:', quality);
                    this.showNotification(`Ses kalitesi ${quality} olarak ayarlandı`, 'success');
                })
                .catch(error => {
                    console.error('❌ Failed to update audio quality:', error);
                    this.showNotification('Ses kalitesi güncellenemedi', 'error');
                });
        }
    }
    
    /**
     * Handle before unload
     */
    handleBeforeUnload() {
        if (this.currentRoom) {
            this.socket.emit('leave-room', { roomId: this.currentRoom.id });
        }
        
        // Close all peer connections
        this.peerConnections.forEach(pc => pc.close());
        
        if (this.socket) {
            this.socket.disconnect();
        }
    }
    
    /**
     * Handle window resize
     */
    handleResize() {
        if (window.innerWidth <= 768) {
            const sidebar = document.getElementById('sidebar');
            if (sidebar && !sidebar.classList.contains('collapsed')) {
                sidebar.classList.add('collapsed');
            }
        }
    }
    
    // Public Methods
    
    /**
     * Join a room
     */
    joinRoom(roomId, password = null) {
        if (!this.socket || !this.isConnected) {
            this.showNotification('Sunucuya bağlı değilsiniz', 'error');
            return;
        }
        
        console.log('🚪 Joining room:', roomId);
        this.socket.emit('join-room', { roomId, password });
    }
    
    /**
     * Leave current room
     */
    leaveRoom() {
        if (!this.currentRoom) return;
        
        console.log('🚪 Leaving room:', this.currentRoom.id);
        this.socket.emit('leave-room', { roomId: this.currentRoom.id });
        
        // Close all peer connections
        this.peerConnections.forEach(pc => pc.close());
        this.peerConnections.clear();
        
        // Reset UI
        const roomContent = document.getElementById('roomContent');
        if (roomContent) {
            roomContent.style.display = 'none';
        }
        
        const welcomeScreen = document.getElementById('welcomeScreen');
        if (welcomeScreen) {
            welcomeScreen.style.display = 'block';
        }
        
        const participantsGrid = document.getElementById('participantsGrid');
        if (participantsGrid) {
            participantsGrid.innerHTML = '';
        }
        
        this.currentRoom = null;
        this.showNotification('Odadan ayrıldınız', 'info');
    }
    
    /**
     * Toggle microphone mute
     */
    toggleMute() {
        this.audioSettings.isMuted = !this.audioSettings.isMuted;
        
        const btn = document.getElementById('muteBtn');
        const icon = btn?.querySelector('i');
        
        if (this.localStream) {
            const audioTrack = this.localStream.getAudioTracks()[0];
            if (audioTrack) {
                audioTrack.enabled = !this.audioSettings.isMuted;
            }
        }
        
        if (icon) {
            icon.className = this.audioSettings.isMuted ? 'fas fa-microphone-slash' : 'fas fa-microphone';
        }
        
        if (btn) {
            btn.className = this.audioSettings.isMuted ? 'control-btn muted' : 'control-btn';
        }
        
        // Notify other users
        if (this.currentRoom) {
            this.socket.emit('user-muted', {
                isMuted: this.audioSettings.isMuted,
                roomId: this.currentRoom.id
            });
        }
        
        const status = this.audioSettings.isMuted ? 'kapatıldı' : 'açıldı';
        this.showNotification(`Mikrofon ${status}`, 'info');
    }
    
    /**
     * Toggle volume (deafen)
     */
    toggleVolume() {
        this.audioSettings.isDeafened = !this.audioSettings.isDeafened;
        
        const btn = document.getElementById('volumeBtn');
        const icon = btn?.querySelector('i');
        
        // Mute/unmute all remote audio elements
        document.querySelectorAll('audio[id^="audio-"]').forEach(audio => {
            audio.muted = this.audioSettings.isDeafened;
        });
        
        if (icon) {
            icon.className = this.audioSettings.isDeafened ? 'fas fa-volume-mute' : 'fas fa-volume-up';
        }
        
        if (btn) {
            btn.className = this.audioSettings.isDeafened ? 'control-btn muted' : 'control-btn';
        }
        
        const status = this.audioSettings.isDeafened ? 'kapatıldı' : 'açıldı';
        this.showNotification(`Hoparlör ${status}`, 'info');
    }
    
    /**
     * Toggle sidebar
     */
    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.toggle('collapsed');
        }
    }
    
    /**
     * Logout user
     */
    logout() {
        if (confirm('Çıkış yapmak istediğinizden emin misiniz?')) {
            // Leave current room
            if (this.currentRoom) {
                this.leaveRoom();
            }
            
            // Clear stored data
            localStorage.removeItem('authToken');
            localStorage.removeItem('userData');
            
            // Disconnect socket
            if (this.socket) {
                this.socket.disconnect();
            }
            
            // Redirect to login
            window.location.href = '/login.html';
        }
    }
    
    // Utility Methods
    
    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    /**
     * Format date for display
     */
    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleString('tr-TR');
    }
    
    /**
     * Generate unique ID
     */
    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }
}

// Initialize client when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Make client globally accessible
    window.sonrixClient = new SonrixVoiceClient();
    
    // Global functions for HTML onclick handlers
    window.toggleSidebar = () => window.sonrixClient.toggleSidebar();
    window.toggleMute = () => window.sonrixClient.toggleMute();
    window.toggleVolume = () => window.sonrixClient.toggleVolume();
    window.leaveRoom = () => window.sonrixClient.leaveRoom();
    window.logout = () => window.sonrixClient.logout();
    window.closePasswordModal = () => window.sonrixClient.closePasswordModal();
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SonrixVoiceClient;
}
