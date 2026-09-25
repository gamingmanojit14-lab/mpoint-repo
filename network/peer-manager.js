/**
 * MPOINT NETWORK - Peer Manager (Gossip Protocol)
 * 
 * নেটওয়ার্কের সমস্ত কানেক্টেড পিয়ার (Peers) পরিচালনা করে। 
 * নতুন ট্রানজেকশন বা ব্লক এলে তা ব্রডকাস্ট (Gossip) করার দায়িত্ব এর।
 */

const { EventEmitter } = require('node:events');
const net = require('node:net');
const { Peer } = require('./p2p-tcp.js');

class PeerManager extends EventEmitter {
    constructor(maxPeers = 32) {
        super();
        this.peers = new Map(); // Map<ip:port, Peer>
        this.maxPeers = maxPeers;
    }

    /**
     * Outbound connection (Connecting to seed nodes or discovered peers)
     */
    connectTo(host, port) {
        if (this.peers.size >= this.maxPeers) {
            console.log(`[Network] Max peers reached. Skipping ${host}:${port}`);
            return;
        }

        const address = `${host}:${port}`;
        if (this.peers.has(address)) return; // Already connected

        console.log(`[Network] Connecting outbound to ${address}...`);
        const socket = net.createConnection({ host, port });
        const peer = new Peer(socket, false);
        
        this._bindPeer(peer);
    }

    /**
     * Inbound connection (Someone connected to our server)
     */
    addInboundPeer(socket) {
        if (this.peers.size >= this.maxPeers) {
            console.log(`[Network] Rejecting inbound connection from ${socket.remoteAddress} (Max peers)`);
            socket.destroy();
            return;
        }
        
        console.log(`[Network] Accepted inbound connection from ${socket.remoteAddress}`);
        const peer = new Peer(socket, true);
        this._bindPeer(peer);
    }

    _bindPeer(peer) {
        this.peers.set(peer.peerAddress, peer);

        peer.on('handshake_complete', (p) => {
            console.log(`[Network] Peer Handshake Complete: ${p.peerAddress} (Height: ${p.versionData.best_height})`);
            this.emit('peer_ready', p);
        });

        // Bubble up messages to the main Server logic
        peer.on('message', (msg) => {
            this.emit('message', msg); // msg = { peer, command, payload }
        });

        peer.on('send_version_requested', (p) => {
            this.emit('send_version_requested', p);
        });

        peer.on('disconnected', (p) => {
            console.log(`[Network] Peer disconnected: ${p.peerAddress}`);
            this.peers.delete(p.peerAddress);
        });
    }

    /**
     * Broadcast a message to all connected and handshake-completed peers
     * @param {string} command - 'tx', 'block', 'inv'
     * @param {Uint8Array|Object} payload 
     * @param {Peer} excludePeer - Peer to skip (prevents echoing back to the sender)
     */
    broadcast(command, payload, excludePeer = null) {
        let count = 0;
        for (const peer of this.peers.values()) {
            if (peer.handshakeComplete && peer !== excludePeer) {
                peer.sendMessage(command, payload);
                count++;
            }
        }
        // console.log(`[Network] Broadcasted '${command}' to ${count} peers.`);
    }

    getConnectedCount() {
        return Array.from(this.peers.values()).filter(p => p.handshakeComplete).length;
    }
}

module.exports = { PeerManager };
