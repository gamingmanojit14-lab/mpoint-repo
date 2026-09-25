/**
 * MPOINT NODE - P2P Server & Persistence Engine (V2)
 * 
 * সার্ভারটি এখন LevelDB এর সাথে যুক্ত। রিস্টার্ট দিলেও ডাটা মুছে যাবে না। 
 * স্টার্টআপের সময় ডাটাবেস চেক করে আগের স্টেট রিস্টোর করা হয়।
 */

const net = require('node:net');
const { EventEmitter } = require('node:events');
const { Chain } = require('../core/chain.js');
const { PeerManager } = require('../network/peer-manager.js');
const { parseBlock, parseTransaction } = require('../core/parser.js');
const { BlockHeader, Block } = require('../core/block.js');
const { Transaction, TxIn, TxOut } = require('../core/tx.js');
const { getBlockReward, targetToBits, MAX_TARGET } = require('../core/consensus.js');
const { Storage } = require('./storage/leveldb.js');

const bytesToText = (bytes) => new TextDecoder().decode(bytes);

class NodeServer extends EventEmitter {
    /**
     * @param {number} port - Network port
     * @param {string} dbPath - Custom path for DB. Defaults to unique port folder to avoid locking.
     */
    constructor(port = 0, dbPath = null) {
        super();
        this.port = port;
        this.chain = new Chain();
        this.peerManager = new PeerManager();
        this.server = null;
        
        // If no custom path is given, separate DBs by port so we can run multiple nodes locally
        this.dbPath = dbPath || `./chaindata-${port || 'default'}`;
        this.storage = new Storage(this.dbPath);

        this._bindNetworkEvents();
    }

    /**
     * Start the TCP Server and initialize DB state
     */
    async start() {
        // 1. Open Database
        await this.storage.open();

        // 2. Load Chain State or Initialize Genesis
        await this._initOrLoadState();

        // 3. Start TCP Listening
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

    async stop() {
        if (this.server) this.server.close();
        for (const peer of this.peerManager.peers.values()) {
            peer.disconnect();
        }
        await this.storage.close();
        console.log(`[Node] Shut down gracefully.`);
    }

    connectToPeer(host, port) {
        this.peerManager.connectTo(host, port);
    }

    /**
     * Load existing state from disk, or create Genesis block
     */
    async _initOrLoadState() {
        const state = await this.storage.getChainState();
        
        if (state) {
            console.log(`[Node] Resuming from disk. Best Height: ${state.height} | Tip: ${state.bestHash}`);
            
            // 1. Load UTXO set directly into memory
            this.chain.utxo.utxos = await this.storage.loadAllUTXOs();
            console.log(`[Node] Loaded ${this.chain.utxo.utxos.size} UTXOs into memory.`);

            // 2. Load Blocks sequentially 
            // (In V1 we load all blocks. In production SPV, we'd only keep headers)
            for (let i = 0; i <= state.height; i++) {
                const hash = await this.storage.db.get(this.storage.PREFIX_HEIGHT + i);
                const block = await this.storage.getBlock(hash);
                // Bypass chain.addBlock validation since these blocks were already verified before saving
                this.chain.blocks.push(block); 
            }
            console.log(`[Node] Successfully restored ${this.chain.blocks.length} blocks to memory.`);
        } else {
            console.log(`[Node] No existing database found. Initializing Genesis Block...`);
            
            const genesisReward = getBlockReward(0);
            const coinbase = new Transaction(1, 
                [new TxIn('0000000000000000000000000000000000000000000000000000000000000000', 0xFFFFFFFF, new Uint8Array([0x00]), 0xFFFFFFFF)], 
                [new TxOut(genesisReward, new Uint8Array([0x6a, 0x07, ...new TextEncoder().encode('Genesis')]))]
            );

            const timestamp = 1735689600; // 2025-01-01
            const bits = targetToBits(MAX_TARGET);
            const header = new BlockHeader(1, new Uint8Array(32), new Uint8Array(32), timestamp, bits, 0);
            
            const genesisBlock = new Block(header, [coinbase]);
            genesisBlock.updateMerkleRoot();
            
            while (!this.chain.constructor.getWork(header.bits) || header.getHash()[31] > 0x0F) { 
                header.nonce++;
                if (header.nonce > 1000) break;
            }
            header.bits = bits; 
            
            // Validate, add to RAM, then flush to disk
            this.chain.addBlock(genesisBlock, true);
            await this._persistBlockToDisk(genesisBlock);
            
            console.log(`[Node] Genesis Block Saved: ${header.getId()}`);
        }
    }

    /**
     * Extracts UTXO diffs from a block and flushes block + state + UTXOs to LevelDB
     * (ব্লক একসেপ্ট হওয়ার পর হার্ডড্রাইভে পার্মানেন্টলি সেভ করা)
     */
    async _persistBlockToDisk(block) {
        const height = this.chain.getHeight() - 1; // Since it's already in the blocks array
        
        // 1. Calculate UTXO Diffs (What was added vs spent)
        const addedUTXOs = new Map();
        const removedUTXOs = new Set();

        for (const tx of block.txs) {
            const txid = tx.getId();
            
            // Spent inputs
            if (!this.chain.utxo.isCoinbase(tx)) {
                for (const input of tx.inputs) {
                    removedUTXOs.add(`${input.prevTxid}:${input.prevVout}`);
                }
            }
            
            // New outputs
            for (let i = 0; i < tx.outputs.length; i++) {
                if (tx.outputs[i].scriptPubKey[0] !== 0x6a) { // Ignore OP_RETURN dust
                    addedUTXOs.set(`${txid}:${i}`, {
                        value: tx.outputs[i].value,
                        scriptPubKey: tx.outputs[i].scriptPubKey
                    });
                }
            }
        }

        // 2. Flush to DB atomically
        await this.storage.saveBlock(block, height);
        await this.storage.saveChainState(height, block.header.getId());
        await this.storage.saveUTXOs(addedUTXOs, removedUTXOs);
    }

    _bindNetworkEvents() {
        this.peerManager.on('send_version_requested', (peer) => {
            peer.sendVersion(this.chain.getHeight(), this.chain.blocks[0].header.getId());
        });

        this.peerManager.on('peer_ready', (peer) => {
            const tip = this.chain.getTip();
            peer.sendMessage('getblocks', { locatorHashes: [tip.header.getId()] });
        });

        // Async message router
        this.peerManager.on('message', async (msg) => {
            const { peer, command, payload } = msg;
            try {
                if (command === 'inv') this._handleInv(peer, payload);
                else if (command === 'getdata') this._handleGetData(peer, payload);
                else if (command === 'getblocks') this._handleGetBlocks(peer, payload);
                else if (command === 'block') await this._handleBlock(peer, payload); // Note the await!
                else if (command === 'tx') this._handleTx(peer, payload);
            } catch (err) {
                console.error(`[Node] Error processing ${command}: ${err.message}`);
            }
        });
    }

    // --- Message Handlers (P2P Protocol) ---

    _handleInv(peer, payloadBytes) {
        const inv = JSON.parse(bytesToText(payloadBytes));
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
        if (requestData.items.length > 0) peer.sendMessage('getdata', requestData);
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
        let startIdx = 0;
        for (const hash of req.locatorHashes) {
            const idx = this.chain.blocks.findIndex(b => b.header.getId() === hash);
            if (idx !== -1) {
                startIdx = idx + 1;
                break;
            }
        }
        const blocksToSend = this.chain.blocks.slice(startIdx, startIdx + 500);
        if (blocksToSend.length > 0) {
            const inv = { items: blocksToSend.map(b => ({ type: 'block', hash: b.header.getId() })) };
            peer.sendMessage('inv', inv);
        }
    }

    async _handleBlock(peer, payloadBytes) {
        const block = parseBlock(payloadBytes);
        const blockId = block.header.getId();

        if (this.chain.blocks.some(b => b.header.getId() === blockId)) return;

        try {
            this.chain.addBlock(block); // Validates mathematically and updates RAM
            await this._persistBlockToDisk(block); // Saves permanently
            
            console.log(`[Node] Accepted Block ${blockId} at height ${this.chain.getHeight()}`);
            
            const inv = { items: [{ type: 'block', hash: blockId }] };
            this.peerManager.broadcast('inv', inv, peer);
            
        } catch (e) {
            console.error(`[Node] Rejected block ${blockId}: ${e.message}`);
        }
    }

    _handleTx(peer, payloadBytes) {
        const tx = parseTransaction(payloadBytes).tx;
        try {
            this.chain.mempool.addTx(tx);
            console.log(`[Node] Accepted TX ${tx.getId()} to mempool`);
            this.peerManager.broadcast('inv', { items: [{ type: 'tx', hash: tx.getId() }] }, peer);
        } catch (e) {}
    }

    // --- Internal API (Used by Miners) ---

    async broadcastBlock(block) {
        try {
            this.chain.addBlock(block);
            await this._persistBlockToDisk(block);
            
            this.peerManager.broadcast('inv', { items: [{ type: 'block', hash: block.header.getId() }] });
            console.log(`[Node] Mined and broadcasted block ${block.header.getId()}`);
        } catch (e) {
            console.error("[Node] Failed to apply self-mined block:", e.message);
        }
    }
}

module.exports = { NodeServer };
