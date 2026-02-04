const { Client, GatewayIntentBits, EmbedBuilder, Collection, ActivityType, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle } = require('discord.js');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');
const http = require('http');
const fetch = require('node-fetch');
require('dotenv').config();

class VPSMonitorBot {
    constructor() {
        // Load configuration
        this.loadConfig();
        
        // Discord bot client
        this.client = new Client({
            intents: [
                GatewayIntentBits.Guilds,
                GatewayIntentBits.GuildMessages,
                GatewayIntentBits.DirectMessages,
                GatewayIntentBits.MessageContent,
                GatewayIntentBits.GuildMembers
            ],
            partials: ['CHANNEL', 'MESSAGE', 'GUILD_MEMBER']
        });

        // Database paths - SHARED with main app
        this.dataDir = this.config.dataDir || './var';
        this.sharedDbPath = path.join(this.dataDir, 'vps_monitor.db');
        this.sessionsDbPath = path.join(this.dataDir, 'sessions.db');
        this.uploadsDir = path.join(this.dataDir, 'uploads');
        
        // Ensure directories exist
        this.ensureDirectories();

        // Collections for storing data
        this.admins = new Collection();
        this.nodes = new Collection();
        this.nodeStats = new Collection();
        this.alertCooldown = new Collection();
        this.userSessions = new Collection();
        this.pendingActions = new Collection();
        this.commandContext = new Collection();
        this.socketConnections = new Collection(); // Store Socket.IO connections

        // Socket.IO Server
        this.io = null;
        this.httpServer = null;
        this.socketPort = this.config.socketPort || 3001;

        // Default configuration
        this.config = {
            ...this.config,
            embedColors: {
                online: parseInt(process.env.COLOR_ONLINE, 16) || 0x00FF00,
                offline: parseInt(process.env.COLOR_OFFLINE, 16) || 0xFF0000,
                warning: parseInt(process.env.COLOR_WARNING, 16) || 0xFFA500,
                info: parseInt(process.env.COLOR_INFO, 16) || 0x0099FF,
                critical: parseInt(process.env.COLOR_CRITICAL, 16) || 0xFF0000,
                success: parseInt(process.env.COLOR_SUCCESS, 16) || 0x00FF00,
                danger: parseInt(process.env.COLOR_DANGER, 16) || 0xFF0000
            },
            prefix: process.env.BOT_PREFIX || '!vps',
            initialAdmins: process.env.INITIAL_ADMINS ? process.env.INITIAL_ADMINS.split(',') : [],
            ownerId: process.env.BOT_OWNER_ID || null,
            logLevel: process.env.LOG_LEVEL || 'info',
            enableStatusUpdates: process.env.ENABLE_STATUS_UPDATES !== 'false',
            maxNodes: parseInt(process.env.MAX_NODES) || 500,
            alertThreshold: parseInt(process.env.ALERT_THRESHOLD) || 1,
            syncInterval: parseInt(process.env.SYNC_INTERVAL_MS) || 15000,
            enableSocketIO: process.env.ENABLE_SOCKET_IO !== 'false',
            socketPort: parseInt(process.env.SOCKET_PORT) || 3001,
            socketCorsOrigin: process.env.SOCKET_CORS_ORIGIN || '*',
            mainAppUrl: process.env.VPS_MONITOR_URL || 'http://localhost:3000',
            sessionSecret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production'
        };

        // Shared database connection
        this.db = null;
        
        // Initialize bot
        this.initialize();
    }

    loadConfig() {
        this.config = {
            // Bot token (REQUIRED)
            token: process.env.DISCORD_BOT_TOKEN,
            
            // Database settings (SAME as main app)
            dataDir: process.env.DATA_DIR || './var',
            
            // Monitoring settings
            alertCooldownMinutes: parseInt(process.env.ALERT_COOLDOWN_MINUTES) || 5,
            checkInterval: parseInt(process.env.CHECK_INTERVAL_MS) || 30000,
            alertThreshold: parseInt(process.env.ALERT_THRESHOLD) || 1,
            syncInterval: parseInt(process.env.SYNC_INTERVAL_MS) || 15000,
            apiTimeout: parseInt(process.env.API_TIMEOUT) || 10000,
            
            // Bot behavior
            prefix: process.env.BOT_PREFIX || '!vps',
            ownerId: process.env.BOT_OWNER_ID,
            logLevel: process.env.LOG_LEVEL || 'info',
            enableStatusUpdates: process.env.ENABLE_STATUS_UPDATES !== 'false',
            enableSocketIO: process.env.ENABLE_SOCKET_IO !== 'false',
            maxNodes: parseInt(process.env.MAX_NODES) || 500,
            
            // Socket.IO settings
            socketPort: parseInt(process.env.SOCKET_PORT) || 3001,
            socketCorsOrigin: process.env.SOCKET_CORS_ORIGIN || '*',
            
            // Colors
            colorOnline: process.env.COLOR_ONLINE || '00FF00',
            colorOffline: process.env.COLOR_OFFLINE || 'FF0000',
            colorWarning: process.env.COLOR_WARNING || 'FFA500',
            colorInfo: process.env.COLOR_INFO || '0099FF',
            colorCritical: process.env.COLOR_CRITICAL || 'FF0000',
            colorSuccess: process.env.COLOR_SUCCESS || '00FF00',
            colorDanger: process.env.COLOR_DANGER || 'FF0000',
            
            // Initial admins
            initialAdmins: process.env.INITIAL_ADMINS ? process.env.INITIAL_ADMINS.split(',') : [],
            
            // Advanced settings
            nodeCheckTimeout: parseInt(process.env.NODE_CHECK_TIMEOUT_MS) || 10000,
            retryAttempts: parseInt(process.env.RETRY_ATTEMPTS) || 3,
            retryDelay: parseInt(process.env.RETRY_DELAY_MS) || 5000,
            
            // Main app integration
            vpsMonitorUrl: process.env.VPS_MONITOR_URL || 'http://localhost:3000',
            apiKey: process.env.API_KEY || '',
            
            // Alert customization
            enableRecoveryAlerts: process.env.ENABLE_RECOVERY_ALERTS !== 'false',
            enableDailySummary: process.env.ENABLE_DAILY_SUMMARY !== 'false',
            dailySummaryTime: process.env.DAILY_SUMMARY_TIME || '09:00',
            
            // Logging
            logToFile: process.env.LOG_TO_FILE === 'true',
            logFile: process.env.LOG_FILE || './var/bot.log'
        };
    }

    log(level, message, data = null) {
        const timestamp = new Date().toISOString();
        const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
        
        // Console logging with colors
        const colors = {
            info: '\x1b[36m', // Cyan
            warn: '\x1b[33m', // Yellow
            error: '\x1b[31m', // Red
            debug: '\x1b[35m', // Magenta
            success: '\x1b[32m', // Green
            reset: '\x1b[0m'
        };
        
        const color = colors[level] || colors.reset;
        
        if (data && typeof data === 'object') {
            console.log(`${color}${logMessage}${colors.reset}`, JSON.stringify(data, null, 2));
        } else if (data) {
            console.log(`${color}${logMessage}${colors.reset}`, data);
        } else {
            console.log(`${color}${logMessage}${colors.reset}`);
        }
        
        // File logging
        if (this.config.logToFile) {
            const logEntry = data ? `${logMessage} ${JSON.stringify(data)}\n` : `${logMessage}\n`;
            fs.appendFileSync(this.config.logFile, logEntry, 'utf8');
        }
        
        // Emit log event via Socket.IO
        if (this.io) {
            this.io.emit('bot_log', {
                level,
                message,
                data,
                timestamp
            });
        }
    }

    ensureDirectories() {
        // Create data directory if it doesn't exist
        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
            this.log('info', `Created data directory: ${this.dataDir}`);
        }

        // Create uploads directory if it doesn't exist
        if (!fs.existsSync(this.uploadsDir)) {
            fs.mkdirSync(this.uploadsDir, { recursive: true });
            this.log('info', `Created uploads directory: ${this.uploadsDir}`);
        }

        // Create logs directory if logging to file
        if (this.config.logToFile) {
            const logDir = path.dirname(this.config.logFile);
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }
        }
    }

    async initialize() {
        this.log('success', '🚀 Initializing VPS Monitor Bot with Socket.IO...');
        
        // Initialize shared database connection
        await this.initSharedDatabase();

        // Initialize Socket.IO server
        if (this.config.enableSocketIO) {
            await this.initSocketIO();
        }

        // Set up Discord event listeners
        this.setupDiscordEventListeners();

        // Load initial data
        await this.loadAllData();

        // Start monitoring
        this.startMonitoring();

        // Start Socket.IO event listeners
        this.setupSocketIOEvents();

        this.log('success', '✅ VPS Monitor Bot initialized successfully');
    }

    async initSharedDatabase() {
        return new Promise((resolve, reject) => {
            this.db = new sqlite3.Database(this.sharedDbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
                if (err) {
                    this.log('error', 'Failed to connect to shared database:', err.message);
                    reject(err);
                    return;
                }

                this.log('info', `✅ Connected to shared database: ${this.sharedDbPath}`);
                
                // Enable WAL mode for better concurrency
                this.db.exec(`
                    PRAGMA journal_mode = WAL;
                    PRAGMA foreign_keys = ON;
                    PRAGMA busy_timeout = 30000;
                    PRAGMA synchronous = NORMAL;
                `, (err) => {
                    if (err) {
                        this.log('warn', 'Database optimization failed:', err.message);
                    } else {
                        this.log('info', 'Database optimization completed');
                    }
                });

                // Create bot-specific tables in the SHARED database
                this.createBotTables().then(() => {
                    this.log('info', '✅ Bot tables initialized in shared database');
                    resolve();
                }).catch(reject);
            });
        });
    }

    async createBotTables() {
        return new Promise((resolve, reject) => {
            this.db.serialize(() => {
                // Create bot_admins table
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS bot_admins (
                        discord_id TEXT PRIMARY KEY,
                        user_id INTEGER,
                        username TEXT,
                        role TEXT DEFAULT 'admin',
                        added_by TEXT,
                        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_active DATETIME,
                        notes TEXT,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                `);

                // Create bot_logs table
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS bot_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        level TEXT,
                        message TEXT,
                        data TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                `);

                // Create bot_sync_logs table
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS bot_sync_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        operation TEXT,
                        target TEXT,
                        details TEXT,
                        status TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                `);

                // Create bot_socket_sessions table
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS bot_socket_sessions (
                        socket_id TEXT PRIMARY KEY,
                        discord_id TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_activity DATETIME,
                        disconnected_at DATETIME,
                        FOREIGN KEY(discord_id) REFERENCES bot_admins(discord_id) ON DELETE CASCADE
                    )
                `);

                this.log('info', '✅ Bot tables created');
                resolve();
            });
        });
    }

    async initSocketIO() {
        return new Promise((resolve) => {
            try {
                // Create HTTP server for Socket.IO
                this.httpServer = http.createServer();
                
                // Initialize Socket.IO with CORS
                this.io = new Server(this.httpServer, {
                    cors: {
                        origin: this.config.socketCorsOrigin,
                        methods: ["GET", "POST"]
                    },
                    transports: ['websocket', 'polling'],
                    pingTimeout: 60000,
                    pingInterval: 25000
                });

                // Start server
                this.httpServer.listen(this.socketPort, () => {
                    this.log('success', `✅ Socket.IO server listening on port ${this.socketPort}`);
                    resolve();
                });

                this.httpServer.on('error', (error) => {
                    this.log('error', 'Socket.IO server error:', error.message);
                });

            } catch (error) {
                this.log('error', 'Failed to initialize Socket.IO:', error.message);
                resolve();
            }
        });
    }

    setupSocketIOEvents() {
        if (!this.io) return;

        this.io.on('connection', async (socket) => {
            const socketId = socket.id;
            const ipAddress = socket.handshake.address;
            const userAgent = socket.handshake.headers['user-agent'];
            
            this.log('info', `🔌 Socket.IO client connected: ${socketId}`);

            // Store socket connection
            this.socketConnections.set(socketId, {
                socket,
                discordId: null,
                connectedAt: new Date(),
                lastActivity: new Date()
            });

            // Save socket session to database
            this.db.run(
                `INSERT INTO bot_socket_sessions (socket_id, ip_address, user_agent, connected_at, last_activity) 
                 VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
                [socketId, ipAddress, userAgent]
            );

            // Send initial data to client
            socket.emit('bot_connected', {
                message: 'Connected to VPS Monitor Bot',
                timestamp: new Date().toISOString(),
                nodeCount: this.nodes.size,
                adminCount: this.admins.size,
                wsConnected: true
            });

            // Send current node data
            socket.emit('nodes_update', Array.from(this.nodes.values()));

            // Handle authentication
            socket.on('authenticate', async (data) => {
                try {
                    if (!data || !data.discordId || !data.token) {
                        socket.emit('auth_error', { message: 'Invalid authentication data' });
                        return;
                    }

                    // Verify Discord user (you might want to implement proper token verification)
                    const discordId = data.discordId;
                    const admin = this.admins.get(discordId);
                    
                    if (!admin) {
                        socket.emit('auth_error', { message: 'User is not a bot admin' });
                        return;
                    }

                    // Update socket connection with Discord ID
                    const socketConn = this.socketConnections.get(socketId);
                    if (socketConn) {
                        socketConn.discordId = discordId;
                        this.socketConnections.set(socketId, socketConn);
                    }

                    // Update database
                    this.db.run(
                        `UPDATE bot_socket_sessions SET discord_id = ?, last_activity = CURRENT_TIMESTAMP WHERE socket_id = ?`,
                        [discordId, socketId]
                    );

                    // Update admin last active
                    this.db.run(
                        `UPDATE bot_admins SET last_active = CURRENT_TIMESTAMP WHERE discord_id = ?`,
                        [discordId]
                    );

                    socket.emit('authenticated', {
                        success: true,
                        discordId,
                        username: admin.username,
                        role: admin.role,
                        permissions: this.getAdminPermissions(admin.role)
                    });

                    this.log('info', `Socket ${socketId} authenticated as ${discordId}`);

                } catch (error) {
                    this.log('error', 'Socket authentication error:', error.message);
                    socket.emit('auth_error', { message: 'Authentication failed' });
                }
            });

            // Handle node requests
            socket.on('get_nodes', () => {
                socket.emit('nodes_update', Array.from(this.nodes.values()));
            });

            socket.on('get_node_stats', (nodeId) => {
                const stats = this.nodeStats.get(nodeId);
                if (stats) {
                    socket.emit('node_stats', { nodeId, stats });
                }
            });

            socket.on('get_alerts', async () => {
                const alerts = await this.getActiveAlerts();
                socket.emit('alerts_update', alerts);
            });

            socket.on('get_bot_stats', () => {
                const stats = this.getBotStats();
                socket.emit('bot_stats', stats);
            });

            // Handle commands via socket
            socket.on('bot_command', async (data) => {
                try {
                    const { command, args = [] } = data;
                    const socketConn = this.socketConnections.get(socketId);
                    
                    if (!socketConn || !socketConn.discordId) {
                        socket.emit('command_error', { message: 'Not authenticated' });
                        return;
                    }

                    // Create a mock message object for command handling
                    const mockMessage = {
                        author: { id: socketConn.discordId, bot: false },
                        channel: { type: 1 }, // DM channel
                        content: `${this.config.prefix} ${command} ${args.join(' ')}`,
                        reply: async (content) => {
                            socket.emit('command_response', { content });
                        }
                    };

                    await this.handleCommand(mockMessage, command, args);

                } catch (error) {
                    this.log('error', 'Socket command error:', error.message);
                    socket.emit('command_error', { message: 'Command execution failed' });
                }
            });

            // Handle ping/pong
            socket.on('ping', () => {
                socket.emit('pong', { timestamp: new Date().toISOString() });
            });

            // Update last activity on any event
            socket.onAny(() => {
                const socketConn = this.socketConnections.get(socketId);
                if (socketConn) {
                    socketConn.lastActivity = new Date();
                    this.socketConnections.set(socketId, socketConn);
                    
                    this.db.run(
                        `UPDATE bot_socket_sessions SET last_activity = CURRENT_TIMESTAMP WHERE socket_id = ?`,
                        [socketId]
                    );
                }
            });

            // Handle disconnection
            socket.on('disconnect', (reason) => {
                this.log('info', `Socket.IO client disconnected: ${socketId} - ${reason}`);
                
                // Update database
                this.db.run(
                    `UPDATE bot_socket_sessions SET disconnected_at = CURRENT_TIMESTAMP WHERE socket_id = ?`,
                    [socketId]
                );

                // Remove from connections
                this.socketConnections.delete(socketId);
            });

            socket.on('error', (error) => {
                this.log('error', `Socket error for ${socketId}:`, error.message);
            });
        });

        // Broadcast events from main app or bot
        this.io.on('broadcast', (event, data) => {
            this.io.emit(event, data);
        });
    }

    getAdminPermissions(role) {
        const permissions = {
            owner: ['all'],
            admin: ['view_nodes', 'edit_nodes', 'delete_nodes', 'view_alerts', 'manage_admins', 'view_stats'],
            manager: ['view_nodes', 'edit_nodes', 'view_alerts', 'view_stats'],
            viewer: ['view_nodes', 'view_alerts', 'view_stats']
        };
        return permissions[role] || permissions.viewer;
    }

    async loadAllData() {
        try {
            // Load admins from both Discord and main app
            await this.loadAdmins();
            
            // Load all nodes from main database
            await this.loadAllNodes();
            
            // Load node stats
            await this.loadNodeStats();
            
            // Load alerts
            await this.loadActiveAlerts();
            
            // Add initial admins if specified
            await this.addInitialAdmins();
            
            this.log('info', `✅ Loaded ${this.admins.size} admin(s) and ${this.nodes.size} node(s)`);
            
            // Broadcast via Socket.IO
            this.broadcastNodesUpdate();
            
        } catch (error) {
            this.log('error', 'Error loading data:', error.message);
        }
    }

    async loadAdmins() {
        return new Promise((resolve) => {
            this.db.all(`SELECT * FROM bot_admins`, (err, rows) => {
                if (err) {
                    this.log('error', 'Error loading bot admins:', err.message);
                } else {
                    rows.forEach(row => {
                        this.admins.set(row.discord_id, {
                            discordId: row.discord_id,
                            userId: row.user_id,
                            username: row.username,
                            role: row.role,
                            addedBy: row.added_by,
                            addedAt: row.added_at,
                            lastActive: row.last_active,
                            notes: row.notes
                        });
                    });
                }

                this.syncWithMainAdmins().then(resolve).catch(() => resolve());
            });
        });
    }

    async syncWithMainAdmins() {
        return new Promise((resolve) => {
            this.db.all(`
                SELECT u.id, u.username, u.role 
                FROM users u 
                WHERE u.role IN ('admin', 'manager') 
                AND u.is_active = 1
            `, (err, rows) => {
                if (err) {
                    this.log('error', 'Error syncing with main admins:', err.message);
                    resolve();
                    return;
                }

                rows.forEach(user => {
                    const existingAdmin = Array.from(this.admins.values()).find(a => a.userId === user.id);
                    if (!existingAdmin) {
                        this.db.run(
                            `INSERT OR IGNORE INTO bot_admins (user_id, username, role, added_by, notes) 
                             VALUES (?, ?, ?, ?, ?)`,
                            [user.id, user.username, user.role, 'system', 'Auto-synced from main app'],
                            (err) => {
                                if (err) this.log('error', 'Error adding main admin to bot_admins:', err.message);
                            }
                        );
                    }
                });
                resolve();
            });
        });
    }

    async loadAllNodes() {
        return new Promise((resolve) => {
            this.db.all(`
                SELECT n.*, 
                       ns.cpu_usage, ns.memory_usage, ns.disk_usage, ns.cpu_cores,
                       ns.memory_total, ns.memory_free, ns.disk_total, ns.disk_free,
                       ns.swap_total, ns.swap_free, ns.network_rx, ns.network_tx,
                       ns.uptime, ns.load_average, ns.cpu_temp, ns.processes,
                       ns.os_version, ns.timestamp as last_stats_time,
                       (SELECT COUNT(*) FROM alerts WHERE node_id = n.id AND resolved = 0) as active_alerts
                FROM nodes n
                LEFT JOIN node_stats ns ON ns.id = (
                    SELECT id FROM node_stats 
                    WHERE node_id = n.id 
                    ORDER BY timestamp DESC LIMIT 1
                )
                ORDER BY n.name
                LIMIT ?
            `, [this.config.maxNodes], (err, rows) => {
                if (err) {
                    this.log('error', 'Error loading all nodes:', err.message);
                    resolve();
                    return;
                }

                // Clear existing nodes
                this.nodes.clear();
                
                rows.forEach(node => {
                    const nodeId = node.id.toString();
                    
                    // Store node with all details
                    this.nodes.set(nodeId, {
                        ...node,
                        group_tags: node.group_tags ? node.group_tags.split(',') : [],
                        active_alerts: node.active_alerts || 0,
                        // Calculate percentages
                        memory_percent: node.memory_total > 0 ? ((node.memory_total - node.memory_free) / node.memory_total * 100).toFixed(1) : 0,
                        disk_percent: node.disk_total > 0 ? ((node.disk_total - node.disk_free) / node.disk_total * 100).toFixed(1) : 0,
                        swap_percent: node.swap_total > 0 ? ((node.swap_total - node.swap_free) / node.swap_total * 100).toFixed(1) : 0,
                        // Format values
                        memory_total_gb: (node.memory_total / 1024 / 1024 / 1024).toFixed(2),
                        memory_free_gb: (node.memory_free / 1024 / 1024 / 1024).toFixed(2),
                        disk_total_gb: (node.disk_total / 1024 / 1024 / 1024).toFixed(2),
                        disk_free_gb: (node.disk_free / 1024 / 1024 / 1024).toFixed(2),
                        swap_total_gb: (node.swap_total / 1024 / 1024 / 1024).toFixed(2),
                        swap_free_gb: (node.swap_free / 1024 / 1024 / 1024).toFixed(2),
                        network_rx_mbps: (node.network_rx / 1024 / 1024 * 8).toFixed(2),
                        network_tx_mbps: (node.network_tx / 1024 / 1024 * 8).toFixed(2)
                    });

                    // Store stats separately for quick access
                    if (node.last_stats_time) {
                        this.nodeStats.set(nodeId, {
                            cpu_usage: node.cpu_usage,
                            memory_usage: node.memory_usage,
                            disk_usage: node.disk_usage,
                            cpu_cores: node.cpu_cores,
                            memory_total: node.memory_total,
                            memory_free: node.memory_free,
                            disk_total: node.disk_total,
                            disk_free: node.disk_free,
                            swap_total: node.swap_total,
                            swap_free: node.swap_free,
                            network_rx: node.network_rx,
                            network_tx: node.network_tx,
                            uptime: node.uptime,
                            load_average: node.load_average,
                            cpu_temp: node.cpu_temp,
                            processes: node.processes,
                            os_version: node.os_version,
                            timestamp: node.last_stats_time
                        });
                    }
                });

                this.log('info', `✅ Loaded ${rows.length} nodes from main database`);
                resolve();
            });
        });
    }

    async loadNodeStats() {
        return Promise.resolve();
    }

    async loadActiveAlerts() {
        return new Promise((resolve) => {
            this.db.all(`
                SELECT a.*, n.name as node_name
                FROM alerts a
                LEFT JOIN nodes n ON a.node_id = n.id
                WHERE a.resolved = 0
                ORDER BY a.created_at DESC
                LIMIT 50
            `, (err, rows) => {
                if (err) {
                    this.log('error', 'Error loading active alerts:', err.message);
                    resolve();
                    return;
                }
                resolve(rows);
            });
        });
    }

    async getActiveAlerts() {
        return new Promise((resolve) => {
            this.db.all(`
                SELECT a.*, n.name as node_name, n.is_online
                FROM alerts a
                LEFT JOIN nodes n ON a.node_id = n.id
                WHERE a.resolved = 0
                ORDER BY a.created_at DESC
                LIMIT 50
            `, (err, rows) => {
                if (err) {
                    this.log('error', 'Error getting active alerts:', err.message);
                    resolve([]);
                    return;
                }
                resolve(rows);
            });
        });
    }

    async addInitialAdmins() {
        if (this.config.initialAdmins && this.config.initialAdmins.length > 0) {
            for (const adminId of this.config.initialAdmins) {
                const cleanId = adminId.trim();
                if (cleanId && !this.admins.has(cleanId)) {
                    await this.addAdminToDatabase(cleanId, 'admin', 'system', 'Initial admin from .env');
                }
            }
        }
        
        // Add bot owner as admin if specified
        if (this.config.ownerId && !this.admins.has(this.config.ownerId)) {
            await this.addAdminToDatabase(this.config.ownerId, 'owner', 'system', 'Bot owner from .env');
        }
    }

    async addAdminToDatabase(discordId, role, addedBy, notes) {
        return new Promise((resolve) => {
            this.db.get(
                `SELECT id, username FROM users WHERE username LIKE ? OR email LIKE ? LIMIT 1`,
                [`%${discordId}%`, `%${discordId}%`],
                (err, user) => {
                    this.db.run(
                        `INSERT OR REPLACE INTO bot_admins (discord_id, user_id, username, role, added_by, notes, last_active) 
                         VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                        [
                            discordId,
                            user ? user.id : null,
                            user ? user.username : discordId,
                            role,
                            addedBy,
                            notes
                        ],
                        (err) => {
                            if (err) {
                                this.log('error', `Failed to add admin ${discordId}:`, err.message);
                            } else {
                                this.admins.set(discordId, {
                                    discordId,
                                    userId: user ? user.id : null,
                                    username: user ? user.username : discordId,
                                    role,
                                    addedBy,
                                    addedAt: new Date().toISOString(),
                                    lastActive: new Date().toISOString(),
                                    notes
                                });
                                this.log('info', `✅ Added ${role}: ${discordId}`);
                            }
                            resolve();
                        }
                    );
                }
            );
        });
    }

    setupDiscordEventListeners() {
        // When bot is ready
        this.client.on('ready', async () => {
            this.log('success', `🤖 Logged in as ${this.client.user.tag}!`);
            this.log('info', `📊 Monitoring ${this.nodes.size} nodes`);
            this.log('info', `🏠 Serving ${this.client.guilds.cache.size} guild(s)`);
            this.log('info', `🔌 Socket.IO: ${this.config.enableSocketIO ? `✅ Server running on port ${this.socketPort}` : '❌ Disabled'}`);
            
            if (this.config.enableStatusUpdates) {
                this.updateBotStatus();
                setInterval(() => this.updateBotStatus(), 60000);
            }

            // Send welcome message to admins
            await this.sendWelcomeMessages();
        });

        // Handle messages
        this.client.on('messageCreate', async (message) => {
            if (message.author.bot) return;

            // DM handling
            if (message.channel.type === 1) {
                await this.handleDM(message);
                return;
            }

            // Command handling
            const prefix = this.config.prefix;
            if (!message.content.startsWith(prefix)) return;

            const args = message.content.slice(prefix.length).trim().split(/ +/);
            const command = args.shift().toLowerCase();

            await this.handleCommand(message, command, args);
        });

        // Handle interactions (buttons, modals, etc.)
        this.client.on('interactionCreate', async (interaction) => {
            if (interaction.isButton()) {
                await this.handleButtonInteraction(interaction);
            } else if (interaction.isModalSubmit()) {
                await this.handleModalSubmit(interaction);
            }
        });

        // Error handling
        this.client.on('error', (error) => {
            this.log('error', 'Discord client error:', error.message);
        });

        this.client.on('warn', (info) => {
            this.log('warn', 'Discord client warning:', info);
        });

        this.client.on('disconnect', () => {
            this.log('warn', 'Bot disconnected from Discord');
        });

        this.client.on('reconnecting', () => {
            this.log('info', 'Bot reconnecting to Discord...');
        });
    }

    async sendWelcomeMessages() {
        for (const [discordId, admin] of this.admins) {
            try {
                const adminUser = await this.client.users.fetch(discordId);
                const embed = new EmbedBuilder()
                    .setColor(this.config.embedColors.success)
                    .setTitle('🤖 VPS Monitor Bot - Online')
                    .setDescription(`Bot is now online and monitoring ${this.nodes.size} nodes`)
                    .addFields(
                        { name: 'Bot Status', value: '✅ Online', inline: true },
                        { name: 'Nodes', value: `${this.nodes.size} total`, inline: true },
                        { name: 'Socket.IO', value: this.config.enableSocketIO ? `✅ Port ${this.socketPort}` : '❌ Disabled', inline: true }
                    )
                    .addFields(
                        { name: 'Available Commands', value: `\`${this.config.prefix} help\` - Show all commands\n\`${this.config.prefix} status\` - Node status\n\`${this.config.prefix} nodes\` - List all nodes` },
                        { name: 'Real-time Features', value: '• Live node status updates\n• Instant alert notifications\n• WebSocket API for custom integrations\n• Real-time dashboard updates' }
                    )
                    .setFooter({ text: 'Automatic alerts enabled | Real-time sync with Socket.IO' })
                    .setTimestamp();

                await adminUser.send({ embeds: [embed] });
            } catch (error) {
                this.log('warn', `Could not send welcome message to admin ${discordId}:`, error.message);
            }
        }
    }

    updateBotStatus() {
        if (!this.client.user) return;
        
        const onlineCount = Array.from(this.nodes.values()).filter(n => n.is_online === 1).length;
        const statusText = `🖥️ ${onlineCount}/${this.nodes.size} online`;
        
        this.client.user.setActivity({
            name: statusText,
            type: ActivityType.Watching
        });
    }

    // Socket.IO Broadcasting Methods
    broadcastNodesUpdate() {
        if (!this.io) return;
        
        const nodesArray = Array.from(this.nodes.values());
        this.io.emit('nodes_update', nodesArray);
        
        // Also send node count
        this.io.emit('node_count_update', {
            total: nodesArray.length,
            online: nodesArray.filter(n => n.is_online === 1).length,
            offline: nodesArray.filter(n => n.is_online === 0).length
        });
    }

    broadcastNodeUpdate(nodeId, nodeData) {
        if (!this.io) return;
        
        this.io.emit('node_update', {
            nodeId,
            node: nodeData,
            timestamp: new Date().toISOString()
        });
    }

    broadcastNodeStatsUpdate(nodeId, stats) {
        if (!this.io) return;
        
        this.io.emit('node_stats_update', {
            nodeId,
            stats,
            timestamp: new Date().toISOString()
        });
    }

    broadcastAlert(alert) {
        if (!this.io) return;
        
        this.io.emit('new_alert', {
            alert,
            timestamp: new Date().toISOString()
        });
    }

    broadcastAlertResolved(alertId) {
        if (!this.io) return;
        
        this.io.emit('alert_resolved', {
            alertId,
            timestamp: new Date().toISOString()
        });
    }

    broadcastBotStats() {
        if (!this.io) return;
        
        const stats = this.getBotStats();
        this.io.emit('bot_stats', stats);
    }

    getBotStats() {
        const onlineNodes = Array.from(this.nodes.values()).filter(n => n.is_online === 1).length;
        const totalAlerts = Array.from(this.nodes.values()).reduce((sum, node) => sum + (node.active_alerts || 0), 0);
        const socketConnections = this.socketConnections.size;
        
        return {
            nodes: {
                total: this.nodes.size,
                online: onlineNodes,
                offline: this.nodes.size - onlineNodes
            },
            alerts: {
                total: totalAlerts,
                bySeverity: {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0
                }
            },
            connections: {
                discord: this.client.guilds.cache.size,
                socket: socketConnections,
                admins: this.admins.size
            },
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            timestamp: new Date().toISOString()
        };
    }

    async handleDM(message) {
        const admin = this.admins.get(message.author.id);
        if (!admin) {
            await message.reply('You are not authorized. Contact a bot administrator.');
            return;
        }

        const content = message.content.toLowerCase().trim();
        
        if (content.startsWith('status')) {
            await this.sendNodeStatus(message);
        } else if (content.startsWith('add node')) {
            await this.handleAddNodeDM(message);
        } else if (content.startsWith('remove node')) {
            await this.handleRemoveNodeDM(message);
        } else if (content.startsWith('list nodes') || content.startsWith('nodes')) {
            await this.listNodes(message);
        } else if (content.startsWith('stats')) {
            await this.showBotStats(message);
        } else if (content.startsWith('help')) {
            await this.sendHelpDM(message);
        } else if (content.startsWith('sync')) {
            await this.syncNodes(message);
        } else if (content.startsWith('alerts')) {
            await this.showAlerts(message);
        } else if (content.startsWith('settings')) {
            await this.showBotSettings(message);
        } else if (content.startsWith('dashboard')) {
            await this.showDashboardLink(message);
        } else if (content.startsWith('socket')) {
            await this.showSocketInfo(message);
        } else if (/^node\s+\d+$/.test(content)) {
            const nodeId = content.split(' ')[1];
            await this.showNodeDetails(message, nodeId);
        } else {
            await message.reply('Unknown command. Type `help` for available commands.');
        }
    }

    async handleCommand(message, command, args) {
        const admin = this.admins.get(message.author.id);

        // Public commands
        const publicCommands = ['status', 'help', 'ping', 'nodes', 'node'];
        if (!admin && !publicCommands.includes(command)) {
            await message.reply('You do not have permission to use this command.');
            return;
        }

        try {
            switch (command) {
                case 'status':
                    await this.sendNodeStatus(message);
                    break;
                
                case 'help':
                    await this.sendHelp(message);
                    break;
                
                case 'ping':
                    const start = Date.now();
                    const msg = await message.reply('🏓 Pinging...');
                    const latency = Date.now() - start;
                    
                    // Get Socket.IO connection count
                    const socketCount = this.socketConnections.size;
                    
                    await msg.edit(`🏓 Pong! 
**Discord Latency:** ${latency}ms
**Socket.IO:** ${this.config.enableSocketIO ? '✅ Enabled' : '❌ Disabled'}
**Active Connections:** ${socketCount}
**Database:** ✅ Connected`);
                    break;
                
                case 'nodes':
                    await this.listNodes(message);
                    break;
                
                case 'node':
                    if (args.length > 0) {
                        await this.showNodeDetails(message, args[0]);
                    } else {
                        await message.reply(`Usage: \`${this.config.prefix} node <id>\``);
                    }
                    break;
                
                case 'socket':
                    await this.showSocketInfo(message);
                    break;
                
                case 'addadmin':
                    await this.addAdmin(message, args);
                    break;
                
                case 'removeadmin':
                    await this.removeAdmin(message, args);
                    break;
                
                case 'listadmins':
                    await this.listAdmins(message);
                    break;
                
                case 'addnode':
                    await this.addNode(message, args);
                    break;
                
                case 'editnode':
                    await this.editNode(message, args);
                    break;
                
                case 'deletenode':
                    await this.deleteNode(message, args);
                    break;
                
                case 'regenkey':
                    await this.regenerateApiKey(message, args);
                    break;
                
                case 'sync':
                    await this.syncNodes(message);
                    break;
                
                case 'stats':
                    await this.showBotStats(message);
                    break;
                
                case 'alerts':
                    await this.showAlerts(message);
                    break;
                
                case 'alerttest':
                    await this.testAlert(message);
                    break;
                
                case 'settings':
                    await this.showBotSettings(message);
                    break;
                
                case 'dashboard':
                    await this.showDashboardLink(message);
                    break;
                
                case 'users':
                    await this.listUsers(message);
                    break;
                
                case 'backup':
                    await this.createBackup(message);
                    break;
                
                case 'export':
                    await this.exportData(message, args);
                    break;
                
                case 'restart':
                    await this.restartMonitoring(message);
                    break;
                
                default:
                    await message.reply(`Unknown command. Use \`${this.config.prefix} help\` for available commands.`);
            }
        } catch (error) {
            this.log('error', `Command error (${command}):`, error.message);
            await message.reply('❌ An error occurred while processing the command.');
        }
    }

    async sendNodeStatus(message) {
        const onlineNodes = Array.from(this.nodes.values()).filter(node => node.is_online === 1);
        const offlineNodes = Array.from(this.nodes.values()).filter(node => node.is_online === 0);
        const socketCount = this.socketConnections.size;
        
        const embed = new EmbedBuilder()
            .setColor(offlineNodes.length > 0 ? this.config.embedColors.warning : this.config.embedColors.success)
            .setTitle('📊 VPS Node Status')
            .setDescription(`**Total:** ${this.nodes.size} nodes | **Online:** ${onlineNodes.length} | **Offline:** ${offlineNodes.length}`)
            .addFields(
                { 
                    name: `✅ Online (${onlineNodes.length})`, 
                    value: onlineNodes.slice(0, 6).map(n => 
                        `• ${n.name}${n.location ? ` [${n.location}]` : ''}`
                    ).join('\n') || 'None', 
                    inline: true 
                },
                { 
                    name: `❌ Offline (${offlineNodes.length})`, 
                    value: offlineNodes.slice(0, 6).map(n => 
                        `• ${n.name}${n.location ? ` [${n.location}]` : ''}`
                    ).join('\n') || 'All nodes online!', 
                    inline: true 
                }
            )
            .addFields(
                { 
                    name: '🔌 Real-time Connections', 
                    value: `**Socket.IO:** ${socketCount} connection(s)\n**Discord:** ${this.client.guilds.cache.size} server(s)`, 
                    inline: false 
                },
                { 
                    name: '🔗 Quick Actions', 
                    value: `\`${this.config.prefix} nodes\` - List all nodes\n\`${this.config.prefix} alerts\` - View alerts\n\`${this.config.prefix} socket\` - Socket.IO info\n\`${this.config.prefix} dashboard\` - Web dashboard`, 
                    inline: false 
                }
            )
            .setFooter({ text: `Last sync: ${new Date().toLocaleTimeString()} | Updates: ${this.config.enableSocketIO ? 'Real-time' : 'Polling'}` })
            .setTimestamp();

        await message.reply({ embeds: [embed] });
    }

    async showSocketInfo(message) {
        const socketCount = this.socketConnections.size;
        const connectedAdmins = Array.from(this.socketConnections.values())
            .filter(conn => conn.discordId)
            .map(conn => conn.discordId);
        
        const embed = new EmbedBuilder()
            .setColor(this.config.embedColors.info)
            .setTitle('🔌 Socket.IO Server Information')
            .setDescription(`Real-time WebSocket server for live updates`)
            .addFields(
                { name: 'Status', value: this.config.enableSocketIO ? '✅ Running' : '❌ Disabled', inline: true },
                { name: 'Port', value: this.socketPort.toString(), inline: true },
                { name: 'Connections', value: socketCount.toString(), inline: true },
                { name: 'Protocol', value: 'WebSocket + HTTP Long Polling', inline: true },
                { name: 'CORS Origin', value: this.config.socketCorsOrigin, inline: true },
                { name: 'Ping Interval', value: '25s', inline: true }
            )
            .addFields({
                name: 'Connected Admins',
                value: connectedAdmins.length > 0 
                    ? connectedAdmins.map(id => `<@${id}>`).join(', ')
                    : 'No admins connected via Socket.IO',
                inline: false
            })
            .addFields({
                name: 'Available Events',
                value: '```\nnodes_update\nnode_update\nnode_stats_update\nnew_alert\nalert_resolved\nbot_stats\nbot_log```',
                inline: false
            })
            .addFields({
                name: 'Client Connection Example',
                value: `\`\`\`javascript
const socket = io('http://localhost:${this.socketPort}');
socket.emit('authenticate', { discordId: 'YOUR_ID' });
socket.on('nodes_update', (nodes) => {
    console.log('Live nodes:', nodes);
});
\`\`\``,
                inline: false
            })
            .setFooter({ text: 'Use Socket.IO for real-time dashboards and custom integrations' })
            .setTimestamp();

        await message.reply({ embeds: [embed] });
    }

    async listNodes(message) {
        const nodesArray = Array.from(this.nodes.values());
        const onlineCount = nodesArray.filter(n => n.is_online === 1).length;
        
        const embed = new EmbedBuilder()
            .setColor(this.config.embedColors.info)
            .setTitle('🖥️ All Monitored Nodes')
            .setDescription(`**${onlineCount}/${nodesArray.length} nodes online**\n*Click buttons below for node details*`)
            .setFooter({ text: `Page 1 of ${Math.ceil(nodesArray.length / 10)} | Real-time updates: ${this.config.enableSocketIO ? '✅ Enabled' : '❌ Disabled'}` })
            .setTimestamp();

        // Create paginated view
        const page = parseInt(message.content.split(' ')[1]) || 1;
        const itemsPerPage = 10;
        const startIndex = (page - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        const pageNodes = nodesArray.slice(startIndex, endIndex);

        if (pageNodes.length === 0) {
            embed.setDescription('No nodes found for this page.');
        } else {
            const nodeList = pageNodes.map((node, index) => {
                const status = node.is_online === 1 ? '✅' : '❌';
                const alerts = node.active_alerts > 0 ? `⚠️${node.active_alerts}` : '';
                const groups = node.group_tags && node.group_tags.length > 0 ? ` [${node.group_tags.join(',')}]` : '';
                return `${status} **${node.id}**. ${node.name}${groups} ${alerts}`;
            }).join('\n');
            
            embed.addFields({
                name: `Nodes (${startIndex + 1}-${Math.min(endIndex, nodesArray.length)})`,
                value: nodeList,
                inline: false
            });
        }

        // Create buttons for pagination and actions
        const row = new ActionRowBuilder();
        
        if (page > 1) {
            row.addComponents(
                new ButtonBuilder()
                    .setCustomId(`nodes_page_${page - 1}`)
                    .setLabel('◀️ Previous')
                    .setStyle(ButtonStyle.Primary)
            );
        }
        
        row.addComponents(
            new ButtonBuilder()
                .setCustomId('refresh_nodes')
                .setLabel('🔄 Refresh')
                .setStyle(ButtonStyle.Secondary)
        );
        
        if (endIndex < nodesArray.length) {
            row.addComponents(
                new ButtonBuilder()
                    .setCustomId(`nodes_page_${page + 1}`)
                    .setLabel('Next ▶️')
                    .setStyle(ButtonStyle.Primary)
            );
        }

        // Add quick action buttons for first few nodes
        const actionRow = new ActionRowBuilder();
        pageNodes.slice(0, 5).forEach(node => {
            actionRow.addComponents(
                new ButtonBuilder()
                    .setCustomId(`node_detail_${node.id}`)
                    .setLabel(`#${node.id}`)
                    .setStyle(node.is_online === 1 ? ButtonStyle.Success : ButtonStyle.Danger)
            );
        });

        await message.reply({ 
            embeds: [embed], 
            components: actionRow.components.length > 0 ? [row, actionRow] : [row] 
        });
    }

    async showNodeDetails(message, nodeId) {
        const node = this.nodes.get(nodeId);
        
        if (!node) {
            await message.reply(`❌ Node with ID "${nodeId}" not found.`);
            return;
        }

        const stats = this.nodeStats.get(nodeId);
        const isOnline = node.is_online === 1;
        
        const embed = new EmbedBuilder()
            .setColor(isOnline ? this.config.embedColors.success : this.config.embedColors.danger)
            .setTitle(`🖥️ ${node.name}`)
            .setDescription(`**Status:** ${isOnline ? '✅ Online' : '❌ Offline'}`)
            .addFields(
                { name: 'Node ID', value: node.id.toString(), inline: true },
                { name: 'Monitor Type', value: node.monitor_type || 'agent', inline: true },
                { name: 'Visibility', value: node.public === 1 ? '🌍 Public' : '🔒 Private', inline: true },
                { name: 'Location', value: node.location || 'Unknown', inline: true },
                { name: 'Hostname', value: node.hostname || 'N/A', inline: true },
                { name: 'IP Address', value: node.ip_address || 'N/A', inline: true },
                { name: 'IP Alias', value: node.ip_alias || 'N/A', inline: true },
                { name: 'Group Tags', value: node.group_tags && node.group_tags.length > 0 ? node.group_tags.join(', ') : 'None', inline: true },
                { name: 'Active Alerts', value: node.active_alerts > 0 ? `⚠️ ${node.active_alerts}` : '✅ None', inline: true },
                { name: 'Last Seen', value: node.last_seen ? new Date(node.last_seen).toLocaleString() : 'Never', inline: true }
            );

        // Add API key (masked)
        embed.addFields({
            name: 'API Key',
            value: node.api_key ? `\`${node.api_key.substring(0, 8)}...${node.api_key.substring(node.api_key.length - 8)}\`` : 'Not available',
            inline: false
        });

        // Add stats if available
        if (stats) {
            embed.addFields(
                { 
                    name: '📊 System Stats', 
                    value: `**CPU:** ${stats.cpu_usage?.toFixed(1) || 0}% (${stats.cpu_cores || 1} cores)\n` +
                           `**Memory:** ${node.memory_percent}% (${node.memory_free_gb} GB free / ${node.memory_total_gb} GB total)\n` +
                           `**Disk:** ${node.disk_percent}% (${node.disk_free_gb} GB free / ${node.disk_total_gb} GB total)\n` +
                           `**Swap:** ${node.swap_percent}% (${node.swap_free_gb} GB free / ${node.swap_total_gb} GB total)\n` +
                           `**Network:** ▲ ${node.network_tx_mbps} Mbps / ▼ ${node.network_rx_mbps} Mbps\n` +
                           `**Uptime:** ${this.formatUptime(stats.uptime)}\n` +
                           `**Load:** ${stats.load_average || 'N/A'}\n` +
                           `**Temp:** ${stats.cpu_temp ? `${stats.cpu_temp}°C` : 'N/A'}\n` +
                           `**Processes:** ${stats.processes || 0}\n` +
                           `**OS:** ${stats.os_version || 'Unknown'}`,
                    inline: false 
                }
            );
        }

        // Add Socket.IO info
        embed.addFields({
            name: '🔌 Real-time Updates',
            value: this.config.enableSocketIO 
                ? `**Event:** \`node_update_${nodeId}\`\n**Event:** \`node_stats_update_${nodeId}\`\n*Subscribe via Socket.IO for live stats*`
                : 'Socket.IO disabled',
            inline: false
        });

        // Add timestamp
        if (stats && stats.timestamp) {
            embed.setFooter({ text: `Stats updated: ${new Date(stats.timestamp).toLocaleTimeString()} | Socket.IO: ${this.config.enableSocketIO ? '✅' : '❌'}` });
        }

        embed.setTimestamp();

        // Create action buttons
        const row = new ActionRowBuilder()
            .addComponents(
                new ButtonBuilder()
                    .setCustomId(`node_refresh_${node.id}`)
                    .setLabel('🔄 Refresh')
                    .setStyle(ButtonStyle.Secondary),
                new ButtonBuilder()
                    .setCustomId(`node_edit_${node.id}`)
                    .setLabel('✏️ Edit')
                    .setStyle(ButtonStyle.Primary),
                new ButtonBuilder()
                    .setCustomId(`node_regenkey_${node.id}`)
                    .setLabel('🔑 Regenerate Key')
                    .setStyle(ButtonStyle.Danger),
                new ButtonBuilder()
                    .setCustomId(`node_delete_${node.id}`)
                    .setLabel('🗑️ Delete')
                    .setStyle(ButtonStyle.Danger)
            );

        await message.reply({ embeds: [embed], components: [row] });
    }

    async addNode(message, args) {
        const admin = this.admins.get(message.author.id);
        if (!admin || (admin.role !== 'admin' && admin.role !== 'owner')) {
            await message.reply('❌ You need admin permissions to add nodes.');
            return;
        }

        if (args.length < 1) {
            // Send modal for node creation
            const modal = new ModalBuilder()
                .setCustomId('add_node_modal')
                .setTitle('Add New Node');

            const nameInput = new TextInputBuilder()
                .setCustomId('node_name')
                .setLabel('Node Name')
                .setStyle(TextInputStyle.Short)
                .setRequired(true)
                .setMaxLength(100);

            const hostnameInput = new TextInputBuilder()
                .setCustomId('node_hostname')
                .setLabel('Hostname (optional)')
                .setStyle(TextInputStyle.Short)
                .setRequired(false);

            const locationInput = new TextInputBuilder()
                .setCustomId('node_location')
                .setLabel('Location (optional)')
                .setStyle(TextInputStyle.Short)
                .setRequired(false);

            const groupInput = new TextInputBuilder()
                .setCustomId('node_groups')
                .setLabel('Group Tags (comma separated)')
                .setStyle(TextInputStyle.Short)
                .setRequired(false);

            const monitorTypeInput = new TextInputBuilder()
                .setCustomId('node_monitor_type')
                .setLabel('Monitor Type (agent/ping)')
                .setStyle(TextInputStyle.Short)
                .setValue('agent')
                .setRequired(true);

            const firstActionRow = new ActionRowBuilder().addComponents(nameInput);
            const secondActionRow = new ActionRowBuilder().addComponents(hostnameInput);
            const thirdActionRow = new ActionRowBuilder().addComponents(locationInput);
            const fourthActionRow = new ActionRowBuilder().addComponents(groupInput);
            const fifthActionRow = new ActionRowBuilder().addComponents(monitorTypeInput);

            modal.addComponents(firstActionRow, secondActionRow, thirdActionRow, fourthActionRow, fifthActionRow);

            await message.showModal(modal);
            return;
        }

        // Legacy command format support
        const name = args[0];
        const apiKey = crypto.randomBytes(32).toString('hex');
        
        try {
            this.db.run(
                `INSERT INTO nodes (name, api_key, monitor_type, created_at, updated_at) 
                 VALUES (?, ?, 'agent', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
                [name, apiKey],
                async function(err) {
                    if (err) {
                        this.log('error', 'Error adding node:', err.message);
                        await message.reply('❌ Failed to add node to database.');
                        return;
                    }

                    const nodeId = this.lastID;
                    
                    // Broadcast via Socket.IO
                    this.broadcastNodesUpdate();
                    
                    // Also send specific node added event
                    if (this.io) {
                        this.io.emit('node_added', {
                            nodeId: nodeId,
                            name: name,
                            timestamp: new Date().toISOString()
                        });
                    }

                    const embed = new EmbedBuilder()
                        .setColor(this.config.embedColors.success)
                        .setTitle('✅ Node Added Successfully')
                        .setDescription(`Node "${name}" has been added to the monitoring system`)
                        .addFields(
                            { name: 'Node ID', value: nodeId.toString(), inline: true },
                            { name: 'Name', value: name, inline: true },
                            { name: 'Monitor Type', value: 'agent', inline: true },
                            { name: 'API Key', value: `\`${apiKey}\``, inline: false }
                        )
                        .setFooter({ text: 'Copy and save the API key for node configuration | Real-time updates enabled' })
                        .setTimestamp();

                    await message.reply({ embeds: [embed] });
                    
                    // Reload nodes
                    await this.loadAllNodes();
                }.bind(this)
            );
        } catch (error) {
            this.log('error', 'Error in addNode:', error.message);
            await message.reply('❌ An error occurred while adding the node.');
        }
    }

    async editNode(message, args) {
        if (args.length < 1) {
            await message.reply(`Usage: \`${this.config.prefix} editnode <node_id>\``);
            return;
        }

        const nodeId = args[0];
        const node = this.nodes.get(nodeId);
        
        if (!node) {
            await message.reply(`❌ Node with ID "${nodeId}" not found.`);
            return;
        }

        // Send modal for editing
        const modal = new ModalBuilder()
            .setCustomId(`edit_node_modal_${nodeId}`)
            .setTitle(`Edit Node: ${node.name}`);

        const nameInput = new TextInputBuilder()
            .setCustomId('node_name')
            .setLabel('Node Name')
            .setStyle(TextInputStyle.Short)
            .setValue(node.name)
            .setRequired(true);

        const hostnameInput = new TextInputBuilder()
            .setCustomId('node_hostname')
            .setLabel('Hostname')
            .setStyle(TextInputStyle.Short)
            .setValue(node.hostname || '')
            .setRequired(false);

        const locationInput = new TextInputBuilder()
            .setCustomId('node_location')
            .setLabel('Location')
            .setStyle(TextInputStyle.Short)
            .setValue(node.location || '')
            .setRequired(false);

        const groupInput = new TextInputBuilder()
            .setCustomId('node_groups')
            .setLabel('Group Tags (comma separated)')
            .setStyle(TextInputStyle.Short)
            .setValue(node.group_tags ? node.group_tags.join(', ') : '')
            .setRequired(false);

        const publicInput = new TextInputBuilder()
            .setCustomId('node_public')
            .setLabel('Public (1=yes, 0=no)')
            .setStyle(TextInputStyle.Short)
            .setValue(node.public?.toString() || '1')
            .setRequired(true);

        const firstActionRow = new ActionRowBuilder().addComponents(nameInput);
        const secondActionRow = new ActionRowBuilder().addComponents(hostnameInput);
        const thirdActionRow = new ActionRowBuilder().addComponents(locationInput);
        const fourthActionRow = new ActionRowBuilder().addComponents(groupInput);
        const fifthActionRow = new ActionRowBuilder().addComponents(publicInput);

        modal.addComponents(firstActionRow, secondActionRow, thirdActionRow, fourthActionRow, fifthActionRow);

        await message.showModal(modal);
    }

    async deleteNode(message, args) {
        if (args.length < 1) {
            await message.reply(`Usage: \`${this.config.prefix} deletenode <node_id>\``);
            return;
        }

        const nodeId = args[0];
        const node = this.nodes.get(nodeId);
        
        if (!node) {
            await message.reply(`❌ Node with ID "${nodeId}" not found.`);
            return;
        }

        // Create confirmation embed
        const embed = new EmbedBuilder()
            .setColor(this.config.embedColors.danger)
            .setTitle('🗑️ Delete Node Confirmation')
            .setDescription(`Are you sure you want to delete node **${node.name}**?\n\n**This action cannot be undone!**`)
            .addFields(
                { name: 'Node ID', value: nodeId, inline: true },
                { name: 'Name', value: node.name, inline: true },
                { name: 'Status', value: node.is_online === 1 ? '✅ Online' : '❌ Offline', inline: true },
                { name: 'Location', value: node.location || 'Unknown', inline: true },
                { name: 'Hostname', value: node.hostname || 'N/A', inline: true },
                { name: 'Monitor Type', value: node.monitor_type || 'agent', inline: true }
            )
            .setFooter({ text: 'This will delete all node data including stats and alerts' })
            .setTimestamp();

        // Create confirmation buttons
        const row = new ActionRowBuilder()
            .addComponents(
                new ButtonBuilder()
                    .setCustomId(`confirm_delete_${nodeId}`)
                    .setLabel('✅ Confirm Delete')
                    .setStyle(ButtonStyle.Danger),
                new ButtonBuilder()
                    .setCustomId(`cancel_delete_${nodeId}`)
                    .setLabel('❌ Cancel')
                    .setStyle(ButtonStyle.Secondary)
            );

        await message.reply({ embeds: [embed], components: [row] });
    }

    async regenerateApiKey(message, args) {
        if (args.length < 1) {
            await message.reply(`Usage: \`${this.config.prefix} regenkey <node_id>\``);
            return;
        }

        const nodeId = args[0];
        const node = this.nodes.get(nodeId);
        
        if (!node) {
            await message.reply(`❌ Node with ID "${nodeId}" not found.`);
            return;
        }

        const newApiKey = crypto.randomBytes(32).toString('hex');
        
        this.db.run(
            `UPDATE nodes SET api_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
            [newApiKey, nodeId],
            async (err) => {
                if (err) {
                    this.log('error', 'Error regenerating API key:', err.message);
                    await message.reply('❌ Failed to regenerate API key.');
                    return;
                }

                // Update local cache
                node.api_key = newApiKey;
                this.nodes.set(nodeId, node);

                // Broadcast via Socket.IO
                if (this.io) {
                    this.io.emit('api_key_regenerated', {
                        nodeId: nodeId,
                        nodeName: node.name,
                        timestamp: new Date().toISOString()
                    });
                }

                const embed = new EmbedBuilder()
                    .setColor(this.config.embedColors.warning)
                    .setTitle('🔑 API Key Regenerated')
                    .setDescription(`API key for node **${node.name}** has been regenerated`)
                    .addFields(
                        { name: 'Node ID', value: nodeId, inline: true },
                        { name: 'Node Name', value: node.name, inline: true },
                        { name: 'New API Key', value: `\`${newApiKey}\``, inline: false }
                    )
                    .setFooter({ text: 'Important: Update the node configuration with the new API key' })
                    .setTimestamp();

                await message.reply({ embeds: [embed] });
                
                // Also send to admin via DM for security
                try {
                    const adminUser = await this.client.users.fetch(message.author.id);
                    await adminUser.send({
                        content: `🔑 API Key Regenerated for node **${node.name}**\n\n**New Key:** \`${newApiKey}\`\n\n*Keep this key secure!*`
                    });
                } catch (error) {
                    this.log('warn', `Could not send API key to admin ${message.author.id}:`, error.message);
                }
            }
        );
    }

    async showAlerts(message) {
        const alerts = await this.getActiveAlerts();

        if (alerts.length === 0) {
            await message.reply('✅ No active alerts.');
            return;
        }

        const embed = new EmbedBuilder()
            .setColor(this.config.embedColors.warning)
            .setTitle('⚠️ Active Alerts')
            .setDescription(`**${alerts.length}** active alert(s)`);

        alerts.forEach((alert, index) => {
            const severity = alert.severity || 'warning';
            const severityEmoji = severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : '🟡';
            const nodeStatus = alert.is_online === 1 ? '✅' : '❌';
            
            embed.addFields({
                name: `${severityEmoji} ${alert.type.toUpperCase()} - ${alert.node_name}`,
                value: `**Message:** ${alert.message}\n` +
                       `**Node:** ${nodeStatus} ${alert.node_name} (ID: ${alert.node_id})\n` +
                       `**Time:** ${new Date(alert.created_at).toLocaleString()}\n` +
                       `**Alert ID:** ${alert.id}`,
                inline: false
            });
        });

        // Create action buttons
        const row = new ActionRowBuilder()
            .addComponents(
                new ButtonBuilder()
                    .setCustomId('refresh_alerts')
                    .setLabel('🔄 Refresh')
                    .setStyle(ButtonStyle.Secondary)
            );

        await message.reply({ embeds: [embed], components: [row] });
    }

    async handleNewAlert(alert) {
        this.log('info', `New alert received: ${alert.type} - ${alert.message}`);
        
        // Broadcast via Socket.IO
        this.broadcastAlert(alert);
        
        // Send to all admins
        for (const [discordId, admin] of this.admins) {
            try {
                const adminUser = await this.client.users.fetch(discordId);
                
                const embed = new EmbedBuilder()
                    .setColor(this.config.embedColors.critical)
                    .setTitle(`⚠️ NEW ALERT: ${alert.type.toUpperCase()}`)
                    .setDescription(alert.message)
                    .addFields(
                        { name: 'Node ID', value: alert.node_id.toString(), inline: true },
                        { name: 'Severity', value: alert.severity || 'warning', inline: true },
                        { name: 'Alert ID', value: alert.id.toString(), inline: true }
                    )
                    .setFooter({ text: 'VPS Monitor Alert System | Real-time notification' })
                    .setTimestamp();

                await adminUser.send({ embeds: [embed] });
                
                // Update admin last active
                this.db.run(
                    `UPDATE bot_admins SET last_active = CURRENT_TIMESTAMP WHERE discord_id = ?`,
                    [discordId]
                );
                
            } catch (error) {
                this.log('warn', `Could not send alert to admin ${discordId}:`, error.message);
            }
        }
    }

    async handleNodeUpdate(nodeData) {
        const nodeId = nodeData.id.toString();
        const existingNode = this.nodes.get(nodeId);
        
        if (existingNode) {
            // Update existing node
            Object.assign(existingNode, nodeData);
            this.nodes.set(nodeId, existingNode);
            
            // Update stats if provided
            if (nodeData.cpu_usage !== undefined) {
                this.nodeStats.set(nodeId, {
                    cpu_usage: nodeData.cpu_usage,
                    memory_usage: nodeData.memory_usage,
                    disk_usage: nodeData.disk_usage,
                    cpu_cores: nodeData.cpu_cores,
                    memory_total: nodeData.memory_total,
                    memory_free: nodeData.memory_free,
                    disk_total: nodeData.disk_total,
                    disk_free: nodeData.disk_free,
                    swap_total: nodeData.swap_total,
                    swap_free: nodeData.swap_free,
                    network_rx: nodeData.network_rx,
                    network_tx: nodeData.network_tx,
                    uptime: nodeData.uptime,
                    load_average: nodeData.load_average,
                    cpu_temp: nodeData.cpu_temp,
                    processes: nodeData.processes,
                    os_version: nodeData.os_version,
                    timestamp: new Date().toISOString()
                });
                
                // Broadcast stats update
                this.broadcastNodeStatsUpdate(nodeId, this.nodeStats.get(nodeId));
            }
            
            // Broadcast node update
            this.broadcastNodeUpdate(nodeId, existingNode);
        }
    }

    async handleNodeAdded(nodeId) {
        // Reload the specific node
        this.db.get(`
            SELECT n.*, 
                   ns.cpu_usage, ns.memory_usage, ns.disk_usage,
                   ns.timestamp as last_stats_time
            FROM nodes n
            LEFT JOIN node_stats ns ON ns.id = (
                SELECT id FROM node_stats 
                WHERE node_id = n.id 
                ORDER BY timestamp DESC LIMIT 1
            )
            WHERE n.id = ?
        `, [nodeId], (err, node) => {
            if (err || !node) {
                this.log('error', 'Error loading added node:', err?.message);
                return;
            }

            const nodeIdStr = node.id.toString();
            this.nodes.set(nodeIdStr, {
                ...node,
                group_tags: node.group_tags ? node.group_tags.split(',') : []
            });

            this.log('info', `✅ Node added via main app: ${node.name}`);
            
            // Broadcast nodes update
            this.broadcastNodesUpdate();
        });
    }

    async handleNodeUpdated(nodeId) {
        // Reload the specific node
        this.handleNodeAdded(nodeId);
    }

    async handleNodeDeleted(nodeId) {
        this.nodes.delete(nodeId.toString());
        this.nodeStats.delete(nodeId.toString());
        this.log('info', `🗑️ Node deleted via main app: ${nodeId}`);
        
        // Broadcast nodes update
        this.broadcastNodesUpdate();
        
        // Send specific deleted event
        if (this.io) {
            this.io.emit('node_deleted', {
                nodeId: nodeId,
                timestamp: new Date().toISOString()
            });
        }
    }

    async handleAlertResolved(alertId) {
        // Broadcast via Socket.IO
        this.broadcastAlertResolved(alertId);
        
        // Notify admins about resolved alert
        for (const [discordId, admin] of this.admins) {
            try {
                const adminUser = await this.client.users.fetch(discordId);
                
                const embed = new EmbedBuilder()
                    .setColor(this.config.embedColors.success)
                    .setTitle('✅ Alert Resolved')
                    .setDescription(`Alert #${alertId} has been resolved`)
                    .setTimestamp();

                await adminUser.send({ embeds: [embed] });
            } catch (error) {
                this.log('warn', `Could not send resolution to admin ${discordId}:`, error.message);
            }
        }
    }

    async handleButtonInteraction(interaction) {
        await interaction.deferUpdate();
        
        const customId = interaction.customId;
        
        if (customId.startsWith('node_detail_')) {
            const nodeId = customId.split('_')[2];
            await this.showNodeDetails(interaction, nodeId);
        } else if (customId.startsWith('node_refresh_')) {
            const nodeId = customId.split('_')[2];
            await this.showNodeDetails(interaction, nodeId);
        } else if (customId.startsWith('node_edit_')) {
            const nodeId = customId.split('_')[2];
            await this.editNode(interaction, [nodeId]);
        } else if (customId.startsWith('node_regenkey_')) {
            const nodeId = customId.split('_')[2];
            await this.regenerateApiKey(interaction, [nodeId]);
        } else if (customId.startsWith('node_delete_')) {
            const nodeId = customId.split('_')[2];
            await this.deleteNode(interaction, [nodeId]);
        } else if (customId.startsWith('confirm_delete_')) {
            const nodeId = customId.split('_')[2];
            await this.confirmDeleteNode(interaction, nodeId);
        } else if (customId.startsWith('cancel_delete_')) {
            await interaction.editReply({ content: '✅ Node deletion cancelled.', components: [] });
        } else if (customId === 'refresh_alerts') {
            await this.showAlerts(interaction);
        } else if (customId === 'refresh_nodes') {
            await this.loadAllNodes();
            await this.listNodes(interaction);
        } else if (customId.startsWith('nodes_page_')) {
            const page = parseInt(customId.split('_')[2]);
            await this.listNodes(interaction, page);
        }
    }

    async handleModalSubmit(interaction) {
        await interaction.deferReply({ ephemeral: true });
        
        const customId = interaction.customId;
        const fields = interaction.fields;
        
        if (customId === 'add_node_modal') {
            const name = fields.getTextInputValue('node_name');
            const hostname = fields.getTextInputValue('node_hostname') || null;
            const location = fields.getTextInputValue('node_location') || 'Unknown';
            const groups = fields.getTextInputValue('node_groups') || '';
            const monitorType = fields.getTextInputValue('node_monitor_type') || 'agent';
            const apiKey = crypto.randomBytes(32).toString('hex');
            
            this.db.run(
                `INSERT INTO nodes (name, hostname, location, group_tags, monitor_type, api_key, created_at, updated_at) 
                 VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
                [name, hostname, location, groups, monitorType, apiKey],
                async function(err) {
                    if (err) {
                        this.log('error', 'Error adding node via modal:', err.message);
                        await interaction.editReply('❌ Failed to add node to database.');
                        return;
                    }

                    const nodeId = this.lastID;
                    
                    // Broadcast via Socket.IO
                    this.broadcastNodesUpdate();
                    
                    if (this.io) {
                        this.io.emit('node_added', {
                            nodeId: nodeId,
                            name: name,
                            timestamp: new Date().toISOString()
                        });
                    }

                    // Reload nodes
                    await this.loadAllNodes();

                    const embed = new EmbedBuilder()
                        .setColor(this.config.embedColors.success)
                        .setTitle('✅ Node Added Successfully')
                        .setDescription(`Node "${name}" has been added to the monitoring system`)
                        .addFields(
                            { name: 'Node ID', value: nodeId.toString(), inline: true },
                            { name: 'Name', value: name, inline: true },
                            { name: 'Hostname', value: hostname || 'N/A', inline: true },
                            { name: 'Location', value: location, inline: true },
                            { name: 'Group Tags', value: groups || 'None', inline: true },
                            { name: 'Monitor Type', value: monitorType, inline: true },
                            { name: 'API Key', value: `\`${apiKey}\``, inline: false }
                        )
                        .setFooter({ text: 'Copy and save the API key for node configuration | Real-time updates enabled' })
                        .setTimestamp();

                    await interaction.editReply({ embeds: [embed] });
                }.bind(this)
            );
        } else if (customId.startsWith('edit_node_modal_')) {
            const nodeId = customId.split('_')[3];
            const name = fields.getTextInputValue('node_name');
            const hostname = fields.getTextInputValue('node_hostname') || null;
            const location = fields.getTextInputValue('node_location') || 'Unknown';
            const groups = fields.getTextInputValue('node_groups') || '';
            const isPublic = fields.getTextInputValue('node_public') === '1' ? 1 : 0;
            
            this.db.run(
                `UPDATE nodes SET name = ?, hostname = ?, location = ?, group_tags = ?, public = ?, updated_at = CURRENT_TIMESTAMP 
                 WHERE id = ?`,
                [name, hostname, location, groups, isPublic, nodeId],
                async (err) => {
                    if (err) {
                        this.log('error', 'Error updating node via modal:', err.message);
                        await interaction.editReply('❌ Failed to update node.');
                        return;
                    }

                    // Broadcast via Socket.IO
                    this.broadcastNodesUpdate();
                    
                    if (this.io) {
                        this.io.emit('node_updated', {
                            nodeId: nodeId,
                            name: name,
                            timestamp: new Date().toISOString()
                        });
                    }

                    // Reload nodes
                    await this.loadAllNodes();

                    const embed = new EmbedBuilder()
                        .setColor(this.config.embedColors.success)
                        .setTitle('✅ Node Updated Successfully')
                        .setDescription(`Node "${name}" has been updated`)
                        .addFields(
                            { name: 'Node ID', value: nodeId, inline: true },
                            { name: 'Name', value: name, inline: true },
                            { name: 'Hostname', value: hostname || 'N/A', inline: true },
                            { name: 'Location', value: location, inline: true },
                            { name: 'Group Tags', value: groups || 'None', inline: true },
                            { name: 'Visibility', value: isPublic === 1 ? 'Public' : 'Private', inline: true }
                        )
                        .setTimestamp();

                    await interaction.editReply({ embeds: [embed] });
                }
            );
        }
    }

    async confirmDeleteNode(interaction, nodeId) {
        this.db.run(`DELETE FROM nodes WHERE id = ?`, [nodeId], async (err) => {
            if (err) {
                this.log('error', 'Error deleting node:', err.message);
                await interaction.editReply({ content: '❌ Failed to delete node.', components: [] });
                return;
            }

            // Broadcast via Socket.IO
            this.broadcastNodesUpdate();
            
            if (this.io) {
                this.io.emit('node_deleted', {
                    nodeId: nodeId,
                    timestamp: new Date().toISOString()
                });
            }

            // Remove from local cache
            this.nodes.delete(nodeId.toString());
            this.nodeStats.delete(nodeId.toString());

            await interaction.editReply({ 
                content: `✅ Node #${nodeId} has been deleted successfully.`, 
                components: [] 
            });
        });
    }

    formatUptime(seconds) {
        if (!seconds) return 'N/A';
        
        const days = Math.floor(seconds / (3600 * 24));
        const hours = Math.floor((seconds % (3600 * 24)) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        let result = '';
        if (days > 0) result += `${days}d `;
        if (hours > 0) result += `${hours}h `;
        if (minutes > 0) result += `${minutes}m`;
        
        return result || `${Math.floor(seconds)}s`;
    }

    startMonitoring() {
        this.log('info', 'Starting real-time monitoring with Socket.IO...');
        
        // Regular sync with database
        setInterval(async () => {
            await this.loadAllNodes();
        }, this.config.syncInterval);

        // Check for offline nodes
        setInterval(() => {
            this.checkOfflineNodes();
        }, 60000);

        // Broadcast bot stats periodically
        setInterval(() => {
            this.broadcastBotStats();
        }, 30000);

        // Clean up old socket sessions
        setInterval(() => {
            this.cleanupSocketSessions();
        }, 60000);

        this.log('info', '✅ Monitoring started with Socket.IO');
    }

    async checkOfflineNodes() {
        const offlineThreshold = 180; // 3 minutes
        const now = new Date();
        
        for (const [nodeId, node] of this.nodes) {
            if (node.is_online === 1) {
                const lastSeen = new Date(node.last_seen);
                const secondsAgo = (now - lastSeen) / 1000;
                
                if (secondsAgo > offlineThreshold) {
                    // Mark as offline
                    node.is_online = 0;
                    this.nodes.set(nodeId, node);
                    
                    // Create offline alert
                    this.db.run(
                        `INSERT INTO alerts (node_id, type, message, severity, created_at) 
                         VALUES (?, 'offline', ?, 'critical', CURRENT_TIMESTAMP)`,
                        [nodeId, `Node ${node.name} has been offline for ${Math.floor(secondsAgo / 60)} minutes`],
                        (err) => {
                            if (!err) {
                                const alert = {
                                    id: this.lastID,
                                    node_id: nodeId,
                                    type: 'offline',
                                    message: `Node ${node.name} is offline`,
                                    severity: 'critical',
                                    created_at: new Date().toISOString()
                                };
                                this.handleNewAlert(alert);
                            }
                        }
                    );
                }
            }
        }
    }

    cleanupSocketSessions() {
        const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
        
        this.db.run(
            `DELETE FROM bot_socket_sessions WHERE connected_at < ?`,
            [cutoff.toISOString()],
            (err) => {
                if (!err) {
                    this.log('debug', 'Cleaned up old socket sessions');
                }
            }
        );
    }

    async login() {
        if (!this.config.token) {
            this.log('error', '❌ No Discord bot token provided in .env file!');
            this.log('error', 'Please set DISCORD_BOT_TOKEN in your .env file');
            process.exit(1);
        }

        try {
            await this.client.login(this.config.token);
        } catch (error) {
            this.log('error', '❌ Failed to login to Discord:', error.message);
            process.exit(1);
        }
    }

    // Helper methods
    extractUserId(input) {
        const mentionMatch = input.match(/<@!?(\d+)>/);
        if (mentionMatch) return mentionMatch[1];
        if (/^\d+$/.test(input)) return input;
        return null;
    }

    async addAdmin(message, args) {
        // Implementation
    }

    async removeAdmin(message, args) {
        // Implementation
    }

    async listAdmins(message) {
        // Implementation
    }

    async showBotStats(message) {
        const stats = this.getBotStats();
        
        const embed = new EmbedBuilder()
            .setColor(this.config.embedColors.info)
            .setTitle('📊 Bot Statistics')
            .setDescription('Real-time monitoring bot performance and status')
            .addFields(
                { name: '📈 Node Statistics', value: `**Total:** ${stats.nodes.total}\n**Online:** ${stats.nodes.online}\n**Offline:** ${stats.nodes.offline}`, inline: true },
                { name: '⚠️ Alert Statistics', value: `**Active:** ${stats.alerts.total}\n**Critical:** ${stats.alerts.bySeverity.critical}\n**High:** ${stats.alerts.bySeverity.high}`, inline: true },
                { name: '🔌 Connections', value: `**Socket.IO:** ${stats.connections.socket}\n**Discord:** ${stats.connections.discord}\n**Admins:** ${stats.connections.admins}`, inline: true },
                { name: '💾 Memory Usage', value: `**RSS:** ${(stats.memory.rss / 1024 / 1024).toFixed(2)} MB\n**Heap:** ${(stats.memory.heapUsed / 1024 / 1024).toFixed(2)} MB`, inline: true },
                { name: '⏱️ Uptime', value: `${Math.floor(stats.uptime / 3600)}h ${Math.floor((stats.uptime % 3600) / 60)}m`, inline: true },
                { name: '🔧 Socket.IO', value: this.config.enableSocketIO ? `✅ Port ${this.socketPort}\n**Clients:** ${stats.connections.socket}` : '❌ Disabled', inline: true }
            )
            .setFooter({ text: 'VPS Monitor Bot - Real-time Statistics' })
            .setTimestamp();

        await message.reply({ embeds: [embed] });
    }

    async showBotSettings(message) {
        const embed = new EmbedBuilder()
            .setColor(this.config.embedColors.info)
            .setTitle('⚙️ Bot Settings')
            .setDescription('Current bot configuration')
            .addFields(
                { name: '🔧 General', value: `**Prefix:** ${this.config.prefix}\n**Max Nodes:** ${this.config.maxNodes}\n**Sync Interval:** ${this.config.syncInterval}ms\n**Log Level:** ${this.config.logLevel}`, inline: true },
                { name: '🔌 Real-time', value: `**Socket.IO:** ${this.config.enableSocketIO ? '✅ Enabled' : '❌ Disabled'}\n**Port:** ${this.socketPort}\n**CORS:** ${this.config.socketCorsOrigin}\n**Status Updates:** ${this.config.enableStatusUpdates ? '✅' : '❌'}`, inline: true },
                { name: '📊 Monitoring', value: `**Alert Cooldown:** ${this.config.alertCooldownMinutes}m\n**Check Interval:** ${this.config.checkInterval}ms\n**API Timeout:** ${this.config.apiTimeout}ms\n**Threshold:** ${this.config.alertThreshold}`, inline: true },
                { name: '👥 Administration', value: `**Admins:** ${this.admins.size}\n**Owner ID:** ${this.config.ownerId || 'Not set'}\n**Initial Admins:** ${this.config.initialAdmins.length}`, inline: true },
                { name: '💾 Storage', value: `**Data Directory:** ${this.dataDir}\n**Database:** ${this.sharedDbPath}\n**Log File:** ${this.config.logToFile ? this.config.logFile : 'Console only'}`, inline: true },
                { name: '🌐 Integration', value: `**Main App URL:** ${this.config.vpsMonitorUrl}\n**API Key:** ${this.config.apiKey ? '✅ Set' : '❌ Not set'}\n**Dashboard:** ${this.config.vpsMonitorUrl}/status`, inline: true }
            )
            .setFooter({ text: 'Settings loaded from .env file and database' })
            .setTimestamp();

        await message.reply({ embeds: [embed] });
    }

    async sendHelp(message) {
        const embed = new EmbedBuilder()
            .setColor(this.config.embedColors.info)
            .setTitle('🤖 VPS Monitor Bot - Help')
            .setDescription(`**Prefix:** \`${this.config.prefix}\`\n**Database:** Shared with VPS Monitor\n**Socket.IO:** ${this.config.enableSocketIO ? `✅ Port ${this.socketPort}` : '❌ Disabled'}`)
            .addFields(
                { 
                    name: '📊 Status Commands', 
                    value: `\`${this.config.prefix} status\` - Node status\n\`${this.config.prefix} nodes\` - List all nodes\n\`${this.config.prefix} node <id>\` - Node details\n\`${this.config.prefix} alerts\` - View alerts\n\`${this.config.prefix} stats\` - Bot statistics\n\`${this.config.prefix} sync\` - Sync with main DB\n\`${this.config.prefix} socket\` - Socket.IO info` 
                },
                { 
                    name: '🖥️ Node Management', 
                    value: `\`${this.config.prefix} addnode\` - Add new node\n\`${this.config.prefix} editnode <id>\` - Edit node\n\`${this.config.prefix} deletenode <id>\` - Delete node\n\`${this.config.prefix} regenkey <id>\` - Regenerate API key` 
                },
                { 
                    name: '👑 Admin Management', 
                    value: `\`${this.config.prefix} addadmin @user\` - Add admin\n\`${this.config.prefix} removeadmin @user\` - Remove admin\n\`${this.config.prefix} listadmins\` - List admins` 
                },
                { 
                    name: '🔧 Utilities', 
                    value: `\`${this.config.prefix} alerttest\` - Test alert\n\`${this.config.prefix} settings\` - Bot settings\n\`${this.config.prefix} ping\` - Check latency\n\`${this.config.prefix} dashboard\` - Web dashboard link\n\`${this.config.prefix} backup\` - Create backup\n\`${this.config.prefix} help\` - This help` 
                },
                { 
                    name: '🔌 Real-time Features', 
                    value: `• Live node status via Socket.IO\n• Instant alert notifications\n• WebSocket API for custom dashboards\n• Real-time bot statistics\n• Connection status monitoring` 
                }
            )
            .setFooter({ text: `Monitoring ${this.nodes.size} nodes | ${this.admins.size} admin(s) | ${this.socketConnections.size} Socket.IO connection(s)` })
            .setTimestamp();

        await message.reply({ embeds: [embed] });
    }

    async sendHelpDM(message) {
        const embed = new EmbedBuilder()
            .setColor(this.config.embedColors.info)
            .setTitle('🤖 VPS Monitor Bot - DM Help')
            .setDescription('Commands available in Direct Messages:')
            .addFields(
                { name: '📊 Status', value: '```status - Check node status\nstats - Show bot statistics\nsync - Sync with main database\nalerts - View active alerts\nsocket - Socket.IO information```' },
                { name: '🖥️ Node Management', value: '```add node - Add new node (interactive)\nremove node <node_id> - Remove node\nlist nodes - List all nodes\nnode <node_id> - Node details```' },
                { name: '🔌 Real-time', value: '```socket - Socket.IO server info\ndashboard - Web dashboard with live updates\nsettings - Bot settings and configuration```' },
                { name: '🔗 Quick Links', value: '```help - Show this help message```' }
            )
            .setFooter({ text: 'Automatic alerts will be sent when nodes go offline | Real-time updates via Socket.IO' })
            .setTimestamp();

        await message.reply({ embeds: [embed] });
    }

    async handleAddNodeDM(message) {
        await this.addNode(message, []);
    }

    async handleRemoveNodeDM(message) {
        const args = message.content.split(' ').slice(2);
        await this.deleteNode(message, args);
    }

    async syncNodes(message) {
        await message.reply('🔄 Syncing with main database...');
        
        try {
            await this.loadAllNodes();
            await message.reply(`✅ Sync complete! Now monitoring ${this.nodes.size} nodes.`);
        } catch (error) {
            await message.reply('❌ Sync failed. Check logs for details.');
        }
    }

    async testAlert(message) {
        // Test alert implementation
        const testAlert = {
            id: Date.now(),
            node_id: 'test',
            type: 'test',
            message: 'This is a test alert',
            severity: 'info',
            created_at: new Date().toISOString()
        };
        
        this.broadcastAlert(testAlert);
        await message.reply('✅ Test alert sent via Socket.IO');
    }

    async showDashboardLink(message) {
        const socketUrl = this.config.enableSocketIO ? `ws://localhost:${this.socketPort}` : 'WebSocket disabled';
        
        const embed = new EmbedBuilder()
            .setColor(this.config.embedColors.info)
            .setTitle('🌐 Web Dashboard & Integration')
            .setDescription(`Access the full web dashboard and integration options:`)
            .addFields(
                { name: '🌐 Web Dashboard', value: `**URL:** ${this.config.mainAppUrl}\n**Admin Panel:** ${this.config.mainAppUrl}/admin\n**Public Status:** ${this.config.mainAppUrl}/status`, inline: true },
                { name: '🔌 Real-time API', value: `**Socket.IO:** ${socketUrl}\n**Events:** nodes_update, node_update, alerts\n**Authentication:** Discord ID + token`, inline: true },
                { name: '📡 Integration', value: '**Custom Dashboards:** Connect via Socket.IO\n**Mobile Apps:** Use WebSocket API\n**Monitoring Tools:** Poll REST endpoints\n**Alert Systems:** Subscribe to alert events', inline: true }
            )
            .addFields({
                name: '🔧 Socket.IO Client Example',
                value: `\`\`\`javascript
// Connect to bot's Socket.IO server
const socket = io('${socketUrl}');

// Authenticate (if needed)
socket.emit('authenticate', { 
    discordId: 'YOUR_DISCORD_ID', 
    token: 'YOUR_TOKEN' 
});

// Listen for real-time updates
socket.on('nodes_update', (nodes) => {
    console.log('Nodes updated:', nodes);
});

socket.on('new_alert', (alert) => {
    console.log('New alert:', alert);
});
\`\`\``,
                inline: false
            })
            .setFooter({ text: 'Use the same credentials as the main dashboard' })
            .setTimestamp();

        await message.reply({ embeds: [embed] });
    }

    async listUsers(message) {
        // Implementation
    }

    async createBackup(message) {
        // Implementation
    }

    async exportData(message, args) {
        // Implementation
    }

    async restartMonitoring(message) {
        // Implementation
    }

    // Socket.IO helper methods for external use
    emitToAll(event, data) {
        if (this.io) {
            this.io.emit(event, data);
        }
    }

    emitToRoom(room, event, data) {
        if (this.io) {
            this.io.to(room).emit(event, data);
        }
    }

    joinRoom(socketId, room) {
        const socket = this.io.sockets.sockets.get(socketId);
        if (socket) {
            socket.join(room);
        }
    }

    leaveRoom(socketId, room) {
        const socket = this.io.sockets.sockets.get(socketId);
        if (socket) {
            socket.leave(room);
        }
    }
}

// Export the bot class
module.exports = VPSMonitorBot;

// If this file is run directly
if (require.main === module) {
    const bot = new VPSMonitorBot();
    bot.login();
}