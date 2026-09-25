/**
 * MPOINT NODE - P2P Server & Synchronization Engine
 * ZERO external dependencies.
 * 
 * এটি একটি সম্পূর্ণ ফুল-নোড সার্ভার। এটি অন্যান্য নোডের সাথে কানেক্ট হয়, 
 * চেইন সিঙ্ক (Sync) করে, এবং নতুন ট্রানজেকশন বা ব্লক এলে তা ভ্যালিডেট করে।
 */

const net = require('node:net');
const { EventEmitter } = require('node:events');
const { Chain } = require('../core/chain.js');
const { PeerManager } = require('../network/peer-manager.js');
const { parseBlock, parseTransaction } = require('../core/parser.js');
const { BlockHeader, Block } = require('../core/block.js');
const { Transaction, TxIn, TxOut } = require('../core/tx.js');
const { getBlockReward, targetToBits, MAX_TARGET } = require('../core/consensus.js');

const bytesToText = (bytes) => new TextDecoder().decode(bytes);

class NodeServer extends EventEmitter {
    constructor(port = 0) {
        super();
        this.port = port;
        this.chain = new Chain();
        this.peerManager = new PeerManager();
        this.server = null;

        // Initialize Genesis Block if chain is empty
        this._initGenesisBlock();

        this._bindNetworkEvents();
    }

    /**
     * Creates a hardcoded Genesis Block so all nodes start from the exact same state.
     * (সব নোডের চেইন একই জেনেসিস ব্লক থেকে শুরু হতে হবে, নতুবা ফর্ক হয়ে যাবে)
     */
    _initGenesisBlock() {
        if (this.chain.getHeight() === 0) {
            const genesisReward = getBlockReward(0);
            // Genesis Tx has 32-zero-byte prevTxid
            const coinbase = new Transaction(1, 
                [new TxIn('0000000000000000000000000000000000000000000000000000000000000000', 0xFFFFFFFF, new Uint8Array([0x00]), 0xFFFFFFFF)], 
                [new TxOut(genesisReward, new Uint8Array([0x6a, 0x07, ...new TextEncoder().encode('Genesis')]))]
            );

            // Fixed timestamp and extremely low difficulty for testnet/v1
            const timestamp = 1735689600; // 2025-01-01
            const bits = targetToBits(MAX_TARGET);
            const header = new BlockHeader(1, new Uint8Array(32), new Uint8Array(32), timestamp, bits, 0);
            
            const genesisBlock = new Block(header, [coinbase]);
            genesisBlock.updateMerkleRoot();
            
            // Dummy PoW solver for Genesis (since it's MAX_TARGET, it solves instantly)
            while (!this.chain.constructor.getWork(header.bits) || header.getHash()[31] > 0x0F) { 
                header.nonce++;
                if (header.nonce > 1000) break; // Prevents hang, MAX_TARGET guarantees quick pass
            }
            header.bits = bits; // Ensure bits aren't accidentally mutated
            
            this.chain.addBlock(genesisBlock, true);
            console.log(`[Node] Genesis Block Initialized: ${header.getId()}`);
        }
    }

    /**
     * Start the TCP Server
     */
    async start() {
        this.server = net.createServer((socket) => {
            this.peerManager.addInboundPeer(socket);
        });

        return new Promise((resolve) => {
            this.server.listen(this.port, '0.0.0.0', () => {
                this.port = this.server.address().port;
                console.log(`[Node] Server listening on port ${this.port}`);
                resolve(this.port);
            });
        });
    }

    stop() {
        if (this.server) this.server.close();
        for (const peer of this.peerManager.peers.values()) {
            peer.disconnect();
        }
    }

    connectToPeer(host, port) {
        this.peerManager.connectTo(host, port);
    }

    _bindNetworkEvents() {
        this.peerManager.on('send_version_requested', (peer) => {
            peer.sendVersion(this.chain.getHeight(), this.chain.blocks[0].header.getId());
        });

        this.peerManager.on('peer_ready', (peer) => {
            // Initiate Sync: Send 'getblocks' requesting inventory
            const tip = this.chain.getTip();
            const locatorHashes = [tip.header.getId()]; // In a real node, this is an array of past hashes
            peer.sendMessage('getblocks', { locatorHashes });
        });

        // The Core Message Router
        this.peerManager.on('message', (msg) => {
            const { peer, command, payload } = msg;

            try {
                if (command === 'inv') this._handleInv(peer, payload);
                else if (command === 'getdata') this._handleGetData(peer, payload);
                else if (command === 'getblocks') this._handleGetBlocks(peer, payload);
                else if (command === 'block') this._handleBlock(peer, payload);
                else if (command === 'tx') this._handleTx(peer, payload);
            } catch (err) {
                console.error(`[Node] Error processing ${command} from ${peer.peerAddress}: ${err.message}`);
            }
        });
    }

    // --- Message Handlers (P2P Protocol) ---

    _handleInv(peer, payloadBytes) {
        const inv = JSON.parse(bytesToText(payloadBytes)); // { items: [{type: 'block', hash: '...'}, ...] }
        const requestData = { items: [] };

        for (const item of inv.items) {
            if (item.type === 'block') {
                const haveBlock = this.chain.blocks.some(b => b.header.getId() === item.hash);
                if (!haveBlock) requestData.items.push(item);
            } else if (item.type === 'tx') {
                const haveTx = this.chain.mempool.txs.has(item.hash);
                if (!haveTx) requestData.items.push(item);
            }
        }

        if (requestData.items.length > 0) {
            peer.sendMessage('getdata', requestData);
        }
    }

    _handleGetData(peer, payloadBytes) {
        const req = JSON.parse(bytesToText(payloadBytes));
        
        for (const item of req.items) {
            if (item.type === 'block') {
                const block = this.chain.blocks.find(b => b.header.getId() === item.hash);
                if (block) peer.sendMessage('block', block.serialize());
            } else if (item.type === 'tx') {
                const tx = this.chain.mempool.txs.get(item.hash);
                if (tx) peer.sendMessage('tx', tx.serialize());
            }
        }
    }

    _handleGetBlocks(peer, payloadBytes) {
        const req = JSON.parse(bytesToText(payloadBytes));
        const locatorHashes = req.locatorHashes;
        
        let startIdx = 0;
        for (const hash of locatorHashes) {
            const idx = this.chain.blocks.findIndex(b => b.header.getId() === hash);
            if (idx !== -1) {
                startIdx = idx + 1;
                break;
            }
        }

        const blocksToSend = this.chain.blocks.slice(startIdx, startIdx + 500); // Max 500 blocks per request
        if (blocksToSend.length > 0) {
            const inv = { items: blocksToSend.map(b => ({ type: 'block', hash: b.header.getId() })) };
            peer.sendMessage('inv', inv);
        }
    }

    _handleBlock(peer, payloadBytes) {
        const block = parseBlock(payloadBytes);
        const blockId = block.header.getId();

        // Check if we already have it
        if (this.chain.blocks.some(b => b.header.getId() === blockId)) return;

        try {
            this.chain.addBlock(block);
            console.log(`[Node] Accepted Block ${blockId} at height ${this.chain.getHeight()}`);
            
            // Broadcast to other peers (Gossip)
            const inv = { items: [{ type: 'block', hash: blockId }] };
            this.peerManager.broadcast('inv', inv, peer); // exclude sender
            
        } catch (e) {
            console.error(`[Node] Rejected block ${blockId} from ${peer.peerAddress}: ${e.message}`);
        }
    }

    _handleTx(peer, payloadBytes) {
        const tx = parseTransaction(payloadBytes).tx;
        const txid = tx.getId();

        try {
            this.chain.mempool.addTx(tx);
            console.log(`[Node] Accepted TX ${txid} to mempool`);
            
            // Broadcast to other peers
            const inv = { items: [{ type: 'tx', hash: txid }] };
            this.peerManager.broadcast('inv', inv, peer);
        } catch (e) {
            // Silently drop invalid mempool txs (could be already confirmed or double-spend)
        }
    }

    // --- Internal API (Used by Miners or Wallets) ---

    broadcastBlock(block) {
        try {
            this.chain.addBlock(block);
            const inv = { items: [{ type: 'block', hash: block.header.getId() }] };
            this.peerManager.broadcast('inv', inv);
            console.log(`[Node] Mined and broadcasted block ${block.header.getId()}`);
        } catch (e) {
            console.error("[Node] Failed to apply self-mined block:", e.message);
        }
    }
}

module.exports = { NodeServer };
