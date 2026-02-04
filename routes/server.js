// routes/server.js
import express from "express";
import axios from "axios";

const router = express.Router();

// Enhanced Cache configuration with adjustable TTL
let cache = {
  data: null,
  timestamp: 0,
  ttl: 100, // 10 seconds for balanced real-time updates and performance
  history: [],
  maxHistory: 500 // Increased for more detailed historical analysis
};

const SERVER_CONFIG = {
  ip: "pvtserver.play.hosting",
  port: "25565",
  name: "PVT X asbag",
  version: "1.8+",
  description: "A Best Minecraft Network",
  website: "website_link",
  discord: "discord_invite_link",
  location: "US",
  region: "US Ohio",
  owner: "asbag",
  started: "2024-01-01",
  features: ["Lifesteal", "Survival", "Economy", "Quests", "Custom Items", "Friendly Community"],
  gamemodes: ["Survival", "Lifesteal"],
  social: {
    discord: "your_discord_invite_link",
    website: "website_link",
    twitter: "leave_blank",
    youtube: "youtube.com/@why_asbag"
  }
};

// Performance monitoring with additional metrics
const performanceStats = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  averageResponseTime: 0,
  uptime: 100,
  lastDowntime: null,
  peakPlayers: 0,
  averageTps: 20,
  lowTpsEvents: 0
};

const isCacheValid = () => {
  return cache.data && (Date.now() - cache.timestamp) < cache.ttl;
};

const addToHistory = (data) => {
  const historyEntry = {
    timestamp: Date.now(),
    online: data.online,
    players: data.players?.online || 0,
    maxPlayers: data.players?.max || 0,
    tps: data.tps || 20,
    responseTime: data.responseTime || 0
  };
  
  cache.history.unshift(historyEntry);
  
  if (cache.history.length > cache.maxHistory) {
    cache.history = cache.history.slice(0, cache.maxHistory);
  }

  // Update peak players
  if (historyEntry.players > performanceStats.peakPlayers) {
    performanceStats.peakPlayers = historyEntry.players;
  }

  // Update average TPS and detect low TPS
  const tpsHistory = cache.history.map(h => h.tps);
  performanceStats.averageTps = tpsHistory.reduce((sum, t) => sum + t, 0) / tpsHistory.length;
  if (historyEntry.tps < 15) {
    performanceStats.lowTpsEvents++;
  }
};

const calculateUptime = () => {
  const last24Hours = cache.history.filter(entry => 
    Date.now() - entry.timestamp < 24 * 60 * 60 * 1000
  );
  
  if (last24Hours.length === 0) return 100;
  
  const onlineCount = last24Hours.filter(entry => entry.online).length;
  return ((onlineCount / last24Hours.length) * 100).toFixed(2);
};

const fetchServerStatus = async () => {
  const startTime = Date.now();
  const endpoints = [
    {
      url: `https://api.mcsrvstat.us/3/${SERVER_CONFIG.ip}:${SERVER_CONFIG.port}`,
      type: 'mcsrvstat_v3'
    },
    {
      url: `https://api.mcsrvstat.us/2/${SERVER_CONFIG.ip}:${SERVER_CONFIG.port}`,
      type: 'mcsrvstat_v2'
    },
    {
      url: `https://api.mcstatus.io/v2/status/java/${SERVER_CONFIG.ip}:${SERVER_CONFIG.port}`,
      type: 'mcstatus'
    },
    {
      url: `https://api.minetools.eu/ping/${SERVER_CONFIG.ip}/${SERVER_CONFIG.port}`,
      type: 'minetools'
    },
    {
      url: `https://mcapi.us/server/status?ip=${SERVER_CONFIG.ip}&port=${SERVER_CONFIG.port}`,
      type: 'mcapi'
    }
  ];

  const responses = await Promise.allSettled(
    endpoints.map(async (endpoint) => {
      try {
        const responseStart = Date.now();
        const response = await axios.get(endpoint.url, { timeout: 3000 }); // Reduced timeout for faster response
        const responseTime = Date.now() - responseStart;
        
        performanceStats.totalRequests++;
        
        if (response.status === 200 && response.data) {
          performanceStats.successfulRequests++;
          return {
            data: response.data,
            time: responseTime,
            type: endpoint.type
          };
        }
      } catch (error) {
        console.log(`Endpoint ${endpoint.type} failed:`, error.message);
        performanceStats.failedRequests++;
      }
      return null;
    })
  );

  const validResponses = responses
    .filter(r => r.status === 'fulfilled' && r.value)
    .map(r => r.value);

  const totalResponseTime = Date.now() - startTime;
  performanceStats.averageResponseTime = 
    (performanceStats.averageResponseTime * (performanceStats.totalRequests - 1) + totalResponseTime) / 
    performanceStats.totalRequests;

  if (validResponses.length === 0) {
    throw new Error("All server status APIs failed");
  }

  // Prefer fastest online response, fallback to fastest overall
  const onlineResponses = validResponses.filter(r => r.data.online);
  let selected = onlineResponses.length > 0 
    ? onlineResponses.reduce((prev, curr) => (prev.time < curr.time ? prev : curr))
    : validResponses.reduce((prev, curr) => (prev.time < curr.time ? prev : curr));

  const normalizedData = normalizeData(selected.data, selected.type);
  normalizedData.responseTime = selected.time;
  normalizedData.dataSource = selected.type;
  
  return normalizedData;
};

const normalizeData = (data, endpointType) => {
  let normalized = {
    online: false,
    ip: SERVER_CONFIG.ip,
    port: SERVER_CONFIG.port,
    hostname: SERVER_CONFIG.ip,
    motd: {
      clean: ['No MOTD available'],
      html: ['No MOTD available'],
      raw: []
    },
    players: {
      online: 0,
      max: 0,
      list: [],
      sample: []
    },
    version: 'Unknown',
    protocol: 0,
    software: 'Unknown',
    plugins: [],
    mods: [],
    map: 'Unknown',
    gamemode: 'Survival',
    icon: null,
    lastUpdated: new Date().toISOString(),
    responseTime: 0,
    dataSource: endpointType,
    tps: 20
  };

  switch (endpointType) {
    case 'mcsrvstat_v3':
    case 'mcsrvstat_v2':
      normalized = {
        ...normalized,
        online: data.online,
        ip: data.ip || SERVER_CONFIG.ip,
        port: data.port || SERVER_CONFIG.port,
        hostname: data.hostname || SERVER_CONFIG.ip,
        motd: {
          clean: Array.isArray(data.motd?.clean) ? data.motd.clean : (data.motd ? data.motd.split('\n') : ['No MOTD available']),
          html: Array.isArray(data.motd?.html) ? data.motd.html : (data.motd ? data.motd.split('\n') : ['No MOTD available']),
          raw: data.motd?.raw || []
        },
        players: {
          online: data.players?.online || 0,
          max: data.players?.max || 0,
          list: data.players?.list || [],
          sample: data.players?.sample || []
        },
        version: data.version || 'Unknown',
        protocol: data.protocol || 0,
        software: data.software || 'Unknown',
        plugins: data.plugins?.names || [],
        mods: data.mods?.names || [],
        map: data.map || 'Unknown',
        gamemode: data.gamemode || 'Survival',
        icon: data.icon || null,
        tps: data.debug?.tps || 20
      };
      break;

    case 'mcstatus':
      normalized = {
        ...normalized,
        online: data.online,
        ip: data.host || SERVER_CONFIG.ip,
        port: data.port || SERVER_CONFIG.port,
        hostname: data.host || SERVER_CONFIG.ip,
        motd: {
          clean: [data.motd?.clean || 'No MOTD available'],
          html: [data.motd?.html || 'No MOTD available'],
          raw: data.motd?.raw || []
        },
        players: {
          online: data.players?.online || 0,
          max: data.players?.max || 0,
          list: data.players?.list?.map(p => p.name_clean) || [],
          sample: data.players?.list?.map(p => ({ name: p.name_clean, id: p.uuid })) || []
        },
        version: data.version?.name_clean || 'Unknown',
        protocol: data.version?.protocol || 0,
        software: data.software || 'Unknown',
        icon: data.icon || null
      };
      break;

    case 'minetools':
      let desc = data.description;
      let cleanText = 'No MOTD available';
      let htmlText = 'No MOTD available';
      if (desc) {
        if (typeof desc === 'string') {
          cleanText = desc;
          htmlText = desc.replace(/\n/g, '<br>');
        } else {
          cleanText = (desc.text || '') + (desc.extra ? desc.extra.map(e => e.text).join('') : '');
          htmlText = (desc.text || '');
          if (desc.extra) {
            desc.extra.forEach(part => {
              let style = '';
              if (part.color) style += `color:${part.color};`;
              if (part.bold) style += 'font-weight:bold;';
              if (part.italic) style += 'font-style:italic;';
              if (part.underlined) style += 'text-decoration:underline;';
              if (part.strikethrough) style += 'text-decoration:line-through;';
              if (part.obfuscated) style += 'font-family:monospace;'; // Simple representation
              htmlText += style ? `<span style="${style}">${part.text}</span>` : part.text;
            });
          }
          htmlText = htmlText.replace(/\n/g, '<br>');
        }
      }
      normalized = {
        ...normalized,
        online: data.online ?? !!data.latency,
        players: {
          online: data.players?.online || 0,
          max: data.players?.max || 0,
          list: data.players?.sample?.map(p => p.name) || [],
          sample: data.players?.sample || []
        },
        version: data.version?.name || 'Unknown',
        protocol: data.version?.protocol || 0,
        motd: {
          clean: cleanText.split('\n'),
          html: [htmlText],
          raw: [desc]
        },
        responseTime: data.latency || 0
      };
      break;

    case 'mcapi':
      normalized = {
        ...normalized,
        online: data.online,
        motd: {
          clean: data.motd ? data.motd.split('\n') : ['No MOTD available'],
          html: data.motd ? data.motd.split('\n').map(line => line.replace(/§[0-9a-fk-or]/g, '')) : ['No MOTD available'], // Strip color codes for html
          raw: [data.motd]
        },
        players: {
          online: data.players_now || 0,
          max: data.players_max || 0,
          list: [],
          sample: []
        },
        version: data.version || 'Unknown',
        software: data.server_modname || 'Unknown'
      };
      break;
  }

  // Fallback icon if not provided
  if (!normalized.icon) {
    normalized.icon = null; // Could add a default base64 icon here if desired
  }

  return normalized;
};

// Real-time monitoring with adjustable interval
const MONITOR_INTERVAL = 10000; // 10 seconds
const startMonitoring = () => {
  setInterval(async () => {
    try {
      const serverData = await fetchServerStatus();
      cache.data = serverData;
      cache.timestamp = Date.now();
      addToHistory(serverData);
      
      // Update uptime statistics
      performanceStats.uptime = calculateUptime();
      
      if (!serverData.online && !performanceStats.lastDowntime) {
        performanceStats.lastDowntime = new Date().toISOString();
      } else if (serverData.online && performanceStats.lastDowntime) {
        performanceStats.lastDowntime = null;
      }
    } catch (error) {
      console.error('Monitoring error:', error.message);
    }
  }, MONITOR_INTERVAL);
};

// Start monitoring when the server starts
startMonitoring();

// Enhanced main route with more data for view
router.get("/", async (req, res, next) => {
  try {
    let serverData;
    
    if (isCacheValid()) {
      serverData = cache.data;
    } else {
      serverData = await fetchServerStatus();
      cache.data = serverData;
      cache.timestamp = Date.now();
      addToHistory(serverData);
    }

    // Calculate additional statistics
    const playerHistory = cache.history.map(h => h.players);
    const avgPlayers = playerHistory.length > 0 
      ? (playerHistory.reduce((a, b) => a + b, 0) / playerHistory.length).toFixed(1)
      : 0;

    const peakPlayers = performanceStats.peakPlayers;
    const uptime = calculateUptime();

    const enhancedData = {
      ...SERVER_CONFIG,
      ...serverData,
      status: serverData.online ? "Online" : "Offline",
      statusColor: serverData.online ? "success" : "danger",
      uptime: uptime + "%",
      performance: {
        responseTime: serverData.responseTime + "ms",
        tps: serverData.tps,
        dataSource: serverData.dataSource,
        averageTps: performanceStats.averageTps.toFixed(2)
      },
      statistics: {
        averagePlayers: avgPlayers,
        peakPlayers: peakPlayers,
        totalQueries: performanceStats.totalRequests,
        successRate: ((performanceStats.successfulRequests / performanceStats.totalRequests) * 100).toFixed(1) + "%",
        lowTpsEvents: performanceStats.lowTpsEvents
      },
      history: cache.history.slice(0, 10), // Last 10 entries
      features: SERVER_CONFIG.features,
      gamemodes: SERVER_CONFIG.gamemodes,
      motdHtml: serverData.motd.html.join('<br>'), // Pre-format for view
      playerList: serverData.players.sample.length > 0 ? serverData.players.sample : serverData.players.list.map(name => ({ name })) // Use sample if available for UUIDs
    };

    res.render("server", { 
      server: enhancedData,
      lastUpdated: new Date(cache.timestamp).toLocaleString(),
      performance: performanceStats,
      history: cache.history.slice(0, 24) // Last 24 entries for charts
    });
  } catch (error) {
    console.error('Error in main route:', error);
    next(error);
  }
});

// New live status system using Server-Sent Events (SSE) for real-time updates
router.get("/api/server/live", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const sendUpdate = () => {
    if (cache.data) {
      res.write(`data: ${JSON.stringify({
        ...cache.data,
        uptime: calculateUptime() + "%",
        averageTps: performanceStats.averageTps.toFixed(2),
        timestamp: new Date().toISOString()
      })}\n\n`);
    }
  };

  sendUpdate(); // Initial send

  const interval = setInterval(sendUpdate, 5000); // Send updates every 5 seconds

  req.on("close", () => {
    clearInterval(interval);
    res.end();
  });
});

// Enhanced API routes
router.get("/api/server/status", async (req, res, next) => {
  try {
    const useCache = req.query.cache !== 'false';
    
    let serverData;
    if (useCache && isCacheValid()) {
      serverData = cache.data;
    } else {
      serverData = await fetchServerStatus();
      cache.data = serverData;
      cache.timestamp = Date.now();
      addToHistory(serverData);
    }

    res.json({
      ...serverData,
      serverInfo: SERVER_CONFIG,
      cached: useCache && isCacheValid(),
      cacheAge: Date.now() - cache.timestamp,
      timestamp: new Date().toISOString(),
      performance: performanceStats,
      statistics: {
        uptime: calculateUptime() + "%",
        averageResponseTime: performanceStats.averageResponseTime.toFixed(2) + "ms",
        averageTps: performanceStats.averageTps.toFixed(2)
      }
    });
  } catch (error) {
    next(error);
  }
});

// Player management endpoints
router.get("/api/server/players", async (req, res, next) => {
  try {
    const serverData = isCacheValid() ? cache.data : await fetchServerStatus();
    
    res.json({
      online: serverData.players.online,
      max: serverData.players.max,
      list: serverData.players.list,
      sample: serverData.players.sample, // Includes UUIDs if available
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
});

// New endpoint for player profile using Mojang API
router.get("/api/player/:uuid", async (req, res, next) => {
  try {
    const { uuid } = req.params;
    const profileResponse = await axios.get(`https://sessionserver.mojang.com/session/minecraft/profile/${uuid.replace(/-/g, '')}`);
    if (profileResponse.status !== 200) {
      return res.status(404).json({ error: "Player profile not found" });
    }
    
    const profile = profileResponse.data;
    // Decode textures
    const textures = JSON.parse(Buffer.from(profile.properties.find(p => p.name === 'textures').value, 'base64').toString());
    
    res.json({
      id: profile.id,
      name: profile.name,
      textures: {
        skin: textures.textures.SKIN?.url,
        cape: textures.textures.CAPE?.url
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Player profile error:', error.message);
    res.status(500).json({ error: "Failed to fetch player profile" });
  }
});

// Plugin and mods information
router.get("/api/server/plugins", async (req, res, next) => {
  try {
    const serverData = isCacheValid() ? cache.data : await fetchServerStatus();
    
    res.json({
      plugins: serverData.plugins || [],
      mods: serverData.mods || [],
      software: serverData.software,
      version: serverData.version,
      totalPlugins: serverData.plugins.length,
      totalMods: serverData.mods.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
});

// Server performance data
router.get("/api/server/performance", (req, res) => {
  const history = cache.history.slice(0, 50); // Last 50 entries
  
  res.json({
    performance: performanceStats,
    history: history,
    charts: {
      players: history.map(h => ({ x: h.timestamp, y: h.players })),
      tps: history.map(h => ({ x: h.timestamp, y: h.tps })),
      responseTime: history.map(h => ({ x: h.timestamp, y: h.responseTime }))
    },
    uptime: calculateUptime() + "%",
    timestamp: new Date().toISOString()
  });
});

// Server information with detailed stats
router.get("/api/server/info", (req, res) => {
  res.json({
    ...SERVER_CONFIG,
    endpoints: {
      status: "/api/server/status",
      players: "/api/server/players",
      playerProfile: "/api/player/:uuid", // New
      plugins: "/api/server/plugins",
      performance: "/api/server/performance",
      live: "/api/server/live",
      health: "/api/health"
    },
    supportedAPIs: ["mcsrvstat.us", "mcstatus.io", "minetools.eu", "mcapi.us"],
    monitoring: {
      enabled: true,
      interval: `${MONITOR_INTERVAL / 1000} seconds`,
      historySize: cache.maxHistory
    },
    features: SERVER_CONFIG.features,
    statistics: {
      totalQueries: performanceStats.totalRequests,
      successRate: ((performanceStats.successfulRequests / performanceStats.totalRequests) * 100).toFixed(1) + "%",
      averageResponseTime: performanceStats.averageResponseTime.toFixed(2) + "ms",
      uptime: calculateUptime() + "%"
    }
  });
});

// Enhanced health check
router.get("/api/health", (req, res) => {
  const health = {
    status: "healthy",
    timestamp: new Date().toISOString(),
    cache: {
      hasData: !!cache.data,
      age: cache.data ? Date.now() - cache.timestamp : 0,
      ttl: cache.ttl,
      historySize: cache.history.length
    },
    performance: performanceStats,
    uptime: calculateUptime() + "%",
    system: {
      memory: process.memoryUsage(),
      uptime: process.uptime(),
      nodeVersion: process.version
    }
  };
  
  res.json(health);
});

// Clear cache with enhanced response
router.post("/api/cache/clear", (req, res) => {
  const oldCacheSize = cache.history.length;
  cache = { 
    data: null, 
    timestamp: 0, 
    ttl: 10000,
    history: [],
    maxHistory: 500
  };
  
  res.json({ 
    success: true, 
    message: "Cache cleared successfully",
    clearedEntries: oldCacheSize,
    timestamp: new Date().toISOString()
  });
});

// Server history endpoint
router.get("/api/server/history", (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const history = cache.history.slice(0, limit);
  
  res.json({
    history: history,
    summary: {
      totalEntries: cache.history.length,
      uptime: calculateUptime() + "%",
      averagePlayers: history.length > 0 ? 
        (history.reduce((sum, entry) => sum + entry.players, 0) / history.length).toFixed(1) : 0,
      peakPlayers: performanceStats.peakPlayers,
      averageTps: performanceStats.averageTps.toFixed(2)
    },
    timestamp: new Date().toISOString()
  });
});

export default router;
