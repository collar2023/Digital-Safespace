import { DurableObject } from "cloudflare:workers";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. WebSocket Connection
    if (url.pathname === "/ws") {
      const roomId = url.searchParams.get("room");
      if (!roomId) return new Response("Missing room ID", { status: 400 });
      const id = env.CHAT_ROOM.idFromName(roomId);
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // 2. [PRIVATE LOGIC] Rate Limit Check for Room Creation
    if (url.pathname === "/check-limit") {
      return await checkRateLimit(request, env);
    }

    // 3. Serve Frontend HTML
    return new Response(HTML_TEMPLATE, {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};

// === [PRIVATE LOGIC] Rate Limit Check Function ===
async function checkRateLimit(request, env) {
  const body = await request.json();
  const { fingerprint, action } = body; 
  
  // Only limit room creation, joining is unlimited.
  if (action !== 'create') {
    return Response.json({ allowed: true });
  }

  const ip = request.headers.get('CF-Connecting-IP');
  
  // Combined Key: fingerprint + IP
  const key = `limit:${fingerprint}:${ip}`;
  const now = Date.now();
  // KV Namespace is USAGE_KV (must be bound in worker settings)
  const record = await env.USAGE_KV.get(key, { type: 'json' });

  // Limit Rule: Max 3 rooms per fingerprint+IP within 24 hours
  const LIMIT = 3;
  const WINDOW = 24 * 60 * 60 * 1000; 

  if (!record) {
    // First use
    await env.USAGE_KV.put(key, JSON.stringify({ count: 1, firstUse: now }), {
      expirationTtl: 86400 // 24 hours TTL
    });
    return Response.json({ allowed: true, remaining: LIMIT - 1 });
  }

  // Check if within the 24-hour window
  if (now - record.firstUse > WINDOW) {
    // Over 24 hours, reset
    await env.USAGE_KV.put(key, JSON.stringify({ count: 1, firstUse: now }), {
      expirationTtl: 86400
    });
    return Response.json({ allowed: true, remaining: LIMIT - 1 });
  }

  // Check count within the window
  if (record.count >= LIMIT) {
    const resetTime = new Date(record.firstUse + WINDOW).toLocaleString('zh-CN');
    return Response.json({ 
      allowed: false, 
      message: `Trial limit reached. Resets after ${resetTime}`,
      remaining: 0 
    });
  }

  // Increment count
  await env.USAGE_KV.put(key, JSON.stringify({ 
    count: record.count + 1, 
    firstUse: record.firstUse 
  }), {
    expirationTtl: 86400
  });

  return Response.json({ 
    allowed: true, 
    remaining: LIMIT - record.count - 1 
  });
}

// === Backend: Durable Object (DO) - Unchanged ===
export class ChatRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sessions = new Set();
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected Websocket", { status: 426 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    await this.handleSession(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async handleSession(ws) {
    ws.accept();
    this.sessions.add(ws);
    ws.addEventListener("message", msg => {
      this.broadcast(msg.data, ws);
    });
    ws.addEventListener("close", () => {
      this.sessions.delete(ws);
    });
  }

  broadcast(message, sender) {
    for (const session of this.sessions) {
      if (session !== sender) {
        try { session.send(message); } 
        catch (err) { this.sessions.delete(session); }
      }
    }
  }
}

// === Frontend: HTML TEMPLATE (Includes private client-side logic for limit check and original encryption functions) ===
const HTML_TEMPLATE = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
  <title>🔒 DIGITAL SAFE</title>
  <style>
    body { background: #121212; color: #e0e0e0; font-family: monospace; margin: 0; display: flex; justify-content: center; height: 100vh; }
    #app { width: 100%; max-width: 600px; display: flex; flex-direction: column; height: 100%; }
    
    #login { padding: 40px; display: flex; flex-direction: column; justify-content: center; height: 100%; }
    h1 { text-align: center; color: #00ff00; letter-spacing: 2px; }
    input { background: #333; border: 1px solid #444; color: white; padding: 15px; margin: 10px 0; border-radius: 4px; font-size: 16px; outline: none; }
    button { background: #006400; color: white; border: none; padding: 15px; font-size: 16px; border-radius: 4px; cursor: pointer; margin-top: 10px; }
    
    #chat { display: none; flex-direction: column; height: 100%; }
    #status-bar { padding: 12px; text-align: center; background: #1e1e1e; border-bottom: 1px solid #333; font-size: 12px; font-weight: bold; }
    .green { color: #00ff00; border-bottom: 2px solid #00ff00; } 
    .red { color: #ff4444; } 
    .yellow { color: #ffff00; }
    
    #messages { flex: 1; overflow-y: auto; padding: 10px; display: flex; flex-direction: column; gap: 10px; }
    .msg { max-width: 80%; padding: 10px; border-radius: 8px; word-wrap: break-word; line-height: 1.4; }
    .msg.me { align-self: flex-end; background: #005c4b; color: white; }
    .msg.other { align-self: flex-start; background: #202c33; color: white; }
    
    #input-area { padding: 15px; background: #1e1e1e; display: flex; gap: 10px; border-top: 1px solid #333; }
    #msgInput { flex: 1; margin: 0; }
    #sendBtn { margin: 0; width: 80px; }
    
    .radio-group { display: flex; gap: 20px; justify-content: center; margin: 15px 0; }
    .radio-group label { cursor: pointer; color: #aaa; }
    .radio-group input { margin-right: 5px; }
    .limit-warning { text-align: center; margin-top: 10px; color: #ff9800; font-size: 13px; }
  </style>
</head>
<body>
  <div id="app">
    <div id="login">
      <h1>DIGITAL SAFE</h1>
      
      <div class="radio-group">
        <label><input type="radio" name="mode" value="create" checked onchange="toggleMode()"> Create Room</label>
        <label><input type="radio" name="mode" value="join" onchange="toggleMode()"> Join Room</label>
      </div>
      
      <input id="room" placeholder="ROOM ID">
      <input id="pass" type="password" placeholder="SECRET KEY">
      <button onclick="enterRoom()">CONNECT</button>
      
      <div id="limitInfo" class="limit-warning"></div>
      <div style="text-align:center; margin-top:20px; color:#444; font-size:12px;">
        Trial Version: 3 room creations allowed per 24h | Unlimited joining
      </div>
    </div>

    <div id="chat">
      <div id="status-bar" class="yellow">Calling Satellite...</div>
      <div id="messages"></div>
      <div id="input-area">
        <input id="msgInput" placeholder="Enter encrypted message..." onkeypress="if(event.key==='Enter') sendMsg()">
        <button id="sendBtn" onclick="sendMsg()">Send</button>
      </div>
    </div>
  </div>

  <script>
    let ws, key, fingerprint, currentMode = 'create';
    const VERIFY_CODE = "HANDSHAKE_OK_V2"; 
    let isHandshakeComplete = false;

    // Generates a browser fingerprint (part of the private limit mechanism)
    async function generateFingerprint() {
      const components = [
        navigator.userAgent, navigator.language, new Date().getTimezoneOffset(),
        screen.width + 'x' + screen.height, screen.colorDepth,
        navigator.hardwareConcurrency || 'unknown', navigator.deviceMemory || 'unknown'
      ];
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top'; ctx.font = '14px Arial'; ctx.fillText('fingerprint', 2, 2);
      components.push(canvas.toDataURL());
      const str = components.join('|||');
      const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
      return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Checks rate limit against the server (private API call)
    async function checkLimit(action) {
      if (!fingerprint) fingerprint = await generateFingerprint();
      const response = await fetch('/check-limit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint, action })
      });
      return await response.json();
    }

    // --- Core E2EE Logic (Same as DigitalSafe-Crypto-Core.js but included here for runtime) ---
    async function deriveKey(password) {
      const enc = new TextEncoder();
      const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
      return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: enc.encode("SIMPLE_SALT_V2"), iterations: 100000, hash: "SHA-256" },
        material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
      );
    }
    async function encrypt(text) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(text);
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
      return JSON.stringify({ iv: Array.from(iv), data: Array.from(new Uint8Array(ciphertext)) });
    }
    async function decrypt(jsonStr) {
      try {
        const body = JSON.parse(jsonStr);
        const iv = new Uint8Array(body.iv);
        const data = new Uint8Array(body.data);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
        return new TextDecoder().decode(decrypted);
      } catch(e) { return null; }
    }
    // -----------------------------------------------------------------------------------------

    function toggleMode() {
      currentMode = document.querySelector('input[name="mode"]:checked').value;
      document.getElementById('limitInfo').textContent = '';
    }

    async function enterRoom() {
      const room = document.getElementById('room').value.trim();
      const pass = document.getElementById('pass').value.trim();
      if(!room || !pass) return alert("Please fill in all fields.");

      // Check limit against the private server logic
      const limitCheck = await checkLimit(currentMode);
      if (!limitCheck.allowed) {
        document.getElementById('limitInfo').textContent = limitCheck.message;
        return;
      }
      
      if (currentMode === 'create' && limitCheck.remaining !== undefined) {
        document.getElementById('limitInfo').textContent = 
          \`Remaining creations: \${limitCheck.remaining}\`;
      }

      key = await deriveKey(pass);
      document.getElementById('login').style.display = 'none';
      document.getElementById('chat').style.display = 'flex';

      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(\`\${proto}//\${location.host}/ws?room=\${room}\`);

      ws.onopen = async () => {
        updateStatus("Connected, sending handshake...", "yellow");
        sendHandshake();
      };

      ws.onmessage = async (e) => {
        const msg = JSON.parse(e.data);
        const text = await decrypt(msg.payload, key);

        if (!text) {
          updateStatus("⚠️ Warning: Invalid key or data detected.", "red");
          return;
        }

        if (msg.type === 'handshake') {
          if (text === VERIFY_CODE) {
            updateStatus("🟢 Secure Channel Established (Peer Verified)", "green");
            if (!isHandshakeComplete) {
                isHandshakeComplete = true;
                sendHandshake(); // Respond with own handshake
            }
          }
          return;
        }

        appendMsg(text, 'other');
      };

      ws.onclose = () => updateStatus("🔴 Connection Disconnected", "red");
    }

    async function sendHandshake() {
      const payload = await encrypt(VERIFY_CODE, key);
      ws.send(JSON.stringify({ type: 'handshake', payload }));
    }

    async function sendMsg() {
      const input = document.getElementById('msgInput');
      const text = input.value;
      if(!text) return;
      const payload = await encrypt(text, key);
      ws.send(JSON.stringify({ type: 'msg', payload }));
      appendMsg(text, 'me');
      input.value = '';
    }

    function appendMsg(text, type) {
      const div = document.createElement('div');
      div.className = \`msg \${type}\`;
      div.textContent = text;
      const box = document.getElementById('messages');
      box.appendChild(div);
      box.scrollTop = box.scrollHeight;
    }

    function updateStatus(text, color) {
      const el = document.getElementById('status-bar');
      el.textContent = text;
      el.className = color;
    }
  </script>
</body>
</html>
`;