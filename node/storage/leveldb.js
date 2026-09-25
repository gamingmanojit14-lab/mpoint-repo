/**
 * MPOINT NODE - LevelDB Storage Interface
 * Uses the 'level' npm package (Allowed per Master Spec §11).
 * 
 * রিস্টার্ট দেওয়ার পর যেন ব্লকচেইন মুছে না যায়, তার জন্য লেভেল-ডিবি (LevelDB) ব্যবহার করে 
 * ডাটা লোকাল হার্ডড্রাইভে সেভ করা হচ্ছে। বিটকয়েন কোর-ও হুবহু এই ডাটাবেস ব্যবহার করে।
 */

const { Level } = require('level');
const { parseBlock } = require('../../core/parser.js');

class Storage {
    /**
     * @param {string} dbPath - Directory to store the database files
     */
    constructor(dbPath = './chaindata') {
        // Initialize LevelDB with JSON value encoding for easy object storage
        this.db = new Level(dbPath, { valueEncoding: 'json' });
        
        // We use prefixes to create "tables" (Sub-levels conceptually)
        this.PREFIX_BLOCK = 'b-';       // b-<block_hash> -> Hex string of block binary
        this.PREFIX_HEIGHT = 'h-';      // h-<height> -> block_hash
        this.PREFIX_UTXO = 'u-';        // u-<txid:vout> -> { value: string, scriptPubKey: hex }
        this.KEY_CHAIN_STATE = 'state'; // { bestHeight: number, bestHash: string }
    }

    async open() {
        await this.db.open();
        console.log(`[Storage] LevelDB opened at ${this.db.location}`);
    }

    async close() {
        await this.db.close();
    }

    /**
     * Save the current chain state (height and tip hash)
     */
    async saveChainState(height, bestHash) {
        await this.db.put(this.KEY_CHAIN_STATE, { height, bestHash });
    }

    /**
     * Load the current chain state on startup
     */
    async getChainState() {
        try {
            return await this.db.get(this.KEY_CHAIN_STATE);
        } catch (err) {
            if (err.code === 'LEVEL_NOT_FOUND') return null; // New node
            throw err;
        }
    }

    /**
     * Save a fully serialized block to disk
     * @param {Block} block - The Block object
     * @param {number} height - The block's height in the chain
     */
    async saveBlock(block, height) {
        const hash = block.header.getId();
        
        // Convert binary Uint8Array to Hex String for safe JSON storage
        const blockHex = Buffer.from(block.serialize()).toString('hex');
        
        const batch = this.db.batch();
        batch.put(this.PREFIX_BLOCK + hash, blockHex);
        batch.put(this.PREFIX_HEIGHT + height, hash);
        
        await batch.write();
    }

    /**
     * Retrieve a block by its Hex ID
     */
    async getBlock(hash) {
        try {
            const blockHex = await this.db.get(this.PREFIX_BLOCK + hash);
            const blockBytes = new Uint8Array(Buffer.from(blockHex, 'hex'));
            return parseBlock(blockBytes); // Parse back to Block object
        } catch (err) {
            if (err.code === 'LEVEL_NOT_FOUND') return null;
            throw err;
        }
    }

    /**
     * UTXO Set Operations
     * BigInt cannot be directly serialized to JSON by default, so we store values as strings.
     * Uint8Arrays are stored as Hex strings.
     */
    async saveUTXOs(addedMap, removedSet) {
        const batch = this.db.batch();
        
        // Delete spent UTXOs
        for (const outpoint of removedSet) {
            batch.del(this.PREFIX_UTXO + outpoint);
        }

        // Add new UTXOs
        for (const [outpoint, utxo] of addedMap.entries()) {
            batch.put(this.PREFIX_UTXO + outpoint, {
                value: utxo.value.toString(), // Convert BigInt to string
                scriptPubKey: Buffer.from(utxo.scriptPubKey).toString('hex')
            });
        }

        await batch.write();
    }

    /**
     * Load the entire UTXO set into memory on startup
     * (নোড স্টার্ট হওয়ার সময় সমস্ত আনস্পেন্ট আউটপুট র‍্যামে লোড করে নেয়)
     */
    async loadAllUTXOs() {
        const utxos = new Map();
        
        // Iterate through all keys starting with 'u-'
        for await (const [key, rawUtxo] of this.db.iterator({ gte: this.PREFIX_UTXO, lt: this.PREFIX_UTXO + '\xFF' })) {
            const outpoint = key.substring(2); // Remove 'u-' prefix
            utxos.set(outpoint, {
                value: BigInt(rawUtxo.value), // Convert string back to BigInt
                scriptPubKey: new Uint8Array(Buffer.from(rawUtxo.scriptPubKey, 'hex'))
            });
        }
        
        return utxos;
    }
}

module.exports = { Storage };
