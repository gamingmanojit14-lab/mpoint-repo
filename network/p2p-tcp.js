/**
 * MPOINT NETWORK - TCP Peer Connection & Buffer Management
 * ZERO external dependencies. Uses Node.js native 'net' and 'events'.
 * 
 * TCP একটি কন্টিনিউয়াস স্ট্রিম। ডাটা ভেঙে ভেঙে (fragmented) আসতে পারে। 
 * এই মডিউলটি ডাটা বাফারে জমা করে এবং সম্পূর্ণ মেসেজ তৈরি হলে ইভেন্ট ফায়ার করে।
 */

const { EventEmitter } = require('node:events');
const net = require('node:net');
const { encodeMessage, decodeMessage } = require('./messages.js');

// Helper to convert objects/strings to Uint8Array for payload
const textToBytes = (text) => new TextEncoder().encode(text);
const bytesToText = (bytes) => new TextDecoder().decode(bytes);

class Peer extends EventEmitter {
    /**
     * @param {net.Socket} socket - Active TCP socket
     * @param {boolean} isInbound - True if they connected to us, False if we connected to them
     */
    constructor(socket, isInbound = false) {
        super();
        this.socket = socket;
        this.isInbound = isInbound;
        this.peerAddress = `${socket.remoteAddress}:${socket.remotePort}`;
        
        this.buffer = Buffer.alloc(0); // Holds incoming TCP stream chunks
        
        this.handshakeComplete = false;
        this.versionData = null; // Will store their 'version' payload

        this._bindEvents();
    }

    _bindEvents() {
        this.socket.on('data', (chunk) => {
            // Append incoming chunk to our buffer (নতুন ডাটা এলে বাফারে জোড়া লাগানো)
            this.buffer = Buffer.concat([this.buffer, chunk]);
            this._processBuffer();
        });

        this.socket.on('error', (err) => {
            console.error(`[Peer ${this.peerAddress}] Socket Error:`, err.message);
            this.disconnect();
        });

        this.socket.on('close', () => {
            this.emit('disconnected', this);
        });
    }

    /**
     * Process the internal buffer to extract complete P2P messages
     * (বাফার থেকে সম্পূর্ণ মেসেজগুলো পার্স করা)
     */
    _processBuffer() {
        while (this.buffer.length >= 24) { // Minimum size for a header is 24 bytes
            try {
                const message = decodeMessage(this.buffer);
                
                // If decodeMessage returns null, the payload hasn't fully arrived yet.
                // We must break and wait for the next 'data' event.
                if (message === null) break; 
                
                // Slice the processed message out of the buffer
                this.buffer = this.buffer.subarray(message.messageLength);
                
                // Route the message to handler
                this._handleMessage(message.command, message.payload);
            } catch (err) {
                // If checksum fails or magic bytes mismatch, the peer is sending garbage.
                // Security rule: Ban/Disconnect misbehaving peers immediately.
                console.error(`[Peer ${this.peerAddress}] Protocol Violation:`, err.message);
                this.disconnect();
                break;
            }
        }
    }

    /**
     * Send a network command with an optional payload
     * @param {string} command - e.g., 'version', 'inv', 'tx'
     * @param {Uint8Array|Object} payload - Binary data or JSON object
     */
    sendMessage(command, payload = new Uint8Array(0)) {
        if (!this.socket.writable) return;

        let payloadBytes;
        if (payload instanceof Uint8Array || Buffer.isBuffer(payload)) {
            payloadBytes = payload; // Already binary (e.g., Block or Tx)
        } else {
            payloadBytes = textToBytes(JSON.stringify(payload)); // JSON for custom metadata like 'version'
        }

        const encoded = encodeMessage(command, payloadBytes);
        this.socket.write(encoded);
    }

    /**
     * Internal router for parsed messages
     */
    _handleMessage(command, payloadBytes) {
        // If not handshake-complete, ONLY allow 'version' or 'verack' commands
        if (!this.handshakeComplete && command !== 'version' && command !== 'verack') {
            console.error(`[Peer ${this.peerAddress}] Sent ${command} before handshake. Disconnecting.`);
            return this.disconnect();
        }

        switch (command) {
            case 'version':
                this._onVersion(payloadBytes);
                break;
            case 'verack':
                this._onVerack();
                break;
            default:
                // For all other commands (tx, block, inv), emit to the Node controller
                this.emit('message', { peer: this, command, payload: payloadBytes });
                break;
        }
    }

    // --- Handshake Logic ---

    /**
     * Step 1: Send our version details
     */
    sendVersion(bestHeight, genesisHash) {
        const myVersion = {
            version: 1,
            user_agent: '/Mpoint:1.0.0/',
            best_height: bestHeight,
            genesis_hash: genesisHash,
            timestamp: Math.floor(Date.now() / 1000)
        };
        this.sendMessage('version', myVersion);
    }

    _onVersion(payloadBytes) {
        try {
            const data = JSON.parse(bytesToText(payloadBytes));
            this.versionData = data;
            
            // Reply with Verack (Acknowledge their version)
            this.sendMessage('verack');
            
            // If they connected to us (Inbound), we also need to send our Version back
            if (this.isInbound) {
                this.emit('send_version_requested', this);
            }
        } catch (e) {
            console.error(`[Peer ${this.peerAddress}] Malformed version payload`);
            this.disconnect();
        }
    }

    _onVerack() {
        this.handshakeComplete = true;
        this.emit('handshake_complete', this);
    }

    disconnect() {
        this.socket.destroy();
        this.emit('disconnected', this);
    }
}

module.exports = { Peer };
