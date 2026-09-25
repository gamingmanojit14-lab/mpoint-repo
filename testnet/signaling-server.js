/**
 * MPOINT - WebRTC Signaling Server
 * 
 * ব্রাউজার ওয়ালেটগুলো একে অপরের সাথে সরাসরি P2P কানেক্ট করার আগে, 
 * আইপি এবং পোর্ট এক্সচেঞ্জ করার জন্য এই সিগন্যালিং সার্ভারটি ব্যবহার করে। 
 * কানেকশন তৈরি হওয়ার পর এর আর কোনো কাজ নেই। এটি কোনো ডাটা সেভ করে না।
 */

const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;
const wss = new WebSocket.Server({ port: PORT });

// Map of connected peers (Key: PeerID, Value: WebSocket)
const peers = new Map();

wss.on('connection', (ws) => {
    // Generate a random Peer ID
    const peerId = 'peer_' + Math.random().toString(36).substr(2, 9);
    peers.set(peerId, ws);
    
    console.log(`[Signal] Connected: ${peerId} (Total: ${peers.size})`);
    
    // Send the assigned ID to the client
    ws.send(JSON.stringify({ type: 'welcome', peerId }));
    
    // Broadcast available peers to the new client (for initial connection)
    const availablePeers = Array.from(peers.keys()).filter(id => id !== peerId);
    ws.send(JSON.stringify({ type: 'peer_list', peers: availablePeers }));

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            // Route WebRTC SDP and ICE candidates to the specific target peer
            if (data.target && peers.has(data.target)) {
                const targetWs = peers.get(data.target);
                data.sender = peerId; // Attach sender ID
                targetWs.send(JSON.stringify(data));
            }
        } catch (e) {
            console.error(`[Signal] Invalid message from ${peerId}`);
        }
    });

    ws.on('close', () => {
        peers.delete(peerId);
        console.log(`[Signal] Disconnected: ${peerId} (Total: ${peers.size})`);
    });
});

console.log(`[Signal] WebRTC Signaling Server running on port ${PORT}`);
