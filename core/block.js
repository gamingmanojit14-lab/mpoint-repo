/**
 * MPOINT CORE - Block & Merkle Tree Data Structures
 * ZERO external dependencies.
 * 
 * বিটকয়েনের হুবহু (bit-for-bit) 80-byte ব্লক হেডার এবং Merkle Tree লজিক ব্যবহার করা হয়েছে।
 */

const { hash256 } = require('./sha256.js');
const { reverseBytes, bytesToHex, hexToBytes } = require('./tx.js');

// --- Helper Utilities for VarInt (Local copy since they weren't exported from tx.js) ---
function varIntSize(n) {
    if (n < 0xfd) return 1;
    if (n <= 0xffff) return 3;
    if (n <= 0xffffffff) return 5;
    return 9;
}

function writeVarInt(view, offset, n) {
    if (n < 0xfd) {
        view.setUint8(offset, n);
        return offset + 1;
    } else if (n <= 0xffff) {
        view.setUint8(offset, 0xfd);
        view.setUint16(offset + 1, n, true); // true = Little-Endian
        return offset + 3;
    } else if (n <= 0xffffffff) {
        view.setUint8(offset, 0xfe);
        view.setUint32(offset + 1, n, true);
        return offset + 5;
    } else {
        view.setUint8(offset, 0xff);
        view.setBigUint64(offset + 1, BigInt(n), true);
        return offset + 9;
    }
}

// --- Merkle Tree Implementation ---

/**
 * Calculate Merkle Root from an array of 32-byte transaction hashes (Little-Endian)
 * বেজোড় (odd) সংখ্যক ট্রানজেকশন থাকলে শেষ ট্রানজেকশনটিকে ডুপ্লিকেট করে জোড় মেলানো হয়।
 * 
 * @param {Uint8Array[]} hashes - Array of 32-byte Uint8Arrays (tx hashes)
 * @returns {Uint8Array} 32-byte Merkle Root
 */
function calculateMerkleRoot(hashes) {
    if (hashes.length === 0) return new Uint8Array(32); // All zeros for empty block

    let level = [...hashes];

    // Tree computation loop
    while (level.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < level.length; i += 2) {
            const left = level[i];
            // If odd number of nodes, duplicate the last one (Bitcoin standard behavior)
            const right = (i + 1 < level.length) ? level[i + 1] : level[i];
            
            // Concatenate Left + Right (64 bytes total)
            const combined = new Uint8Array(64);
            combined.set(left, 0);
            combined.set(right, 32);
            
            // Hash256 the combined bytes
            nextLevel.push(hash256(combined));
        }
        level = nextLevel;
    }
    
    return level[0];
}

// --- Block Classes ---

class BlockHeader {
    /**
     * @param {number} version - Protocol version (usually 1)
     * @param {Uint8Array} prevBlockHash - 32-byte LE hash of previous block
     * @param {Uint8Array} merkleRoot - 32-byte LE Merkle root of transactions
     * @param {number} timestamp - Unix epoch time in seconds
     * @param {number} bits - Compact difficulty target (PoW)
     * @param {number} nonce - Number used once for mining PoW
     */
    constructor(version, prevBlockHash, merkleRoot, timestamp, bits, nonce = 0) {
        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.timestamp = timestamp;
        this.bits = bits;
        this.nonce = nonce;
    }

    /**
     * Serialize header to strictly 80 bytes (Bitcoin format)
     * মেমোরিতে এই ৮০ বাইট ডাটাই শুধু হ্যাশ (PoW) করা হয়।
     * @returns {Uint8Array}
     */
    serialize() {
        const buffer = new Uint8Array(80);
        const view = new DataView(buffer.buffer);
        let offset = 0;

        view.setUint32(offset, this.version, true); offset += 4;
        
        buffer.set(this.prevBlockHash, offset); offset += 32;
        buffer.set(this.merkleRoot, offset); offset += 32;
        
        view.setUint32(offset, this.timestamp, true); offset += 4;
        view.setUint32(offset, this.bits, true); offset += 4;
        view.setUint32(offset, this.nonce, true); offset += 4;

        return buffer;
    }

    /**
     * Get the Block Hash (PoW Hash) -> HASH256(80-byte header)
     */
    getHash() {
        return hash256(this.serialize());
    }

    /**
     * Get Block ID in standard Big-Endian hex format (for explorers/logs)
     */
    getId() {
        return bytesToHex(reverseBytes(this.getHash()));
    }
}

class Block {
    /**
     * @param {BlockHeader} header - The 80-byte header object
     * @param {Transaction[]} txs - Array of Transaction objects
     */
    constructor(header, txs = []) {
        this.header = header;
        this.txs = txs;
    }

    /**
     * Recalculates the Merkle Root from current transactions and updates the header
     * মাইনিং শুরু করার আগে এই মেথড কল করতে হয়।
     */
    updateMerkleRoot() {
        // Extract 32-byte Little-Endian hashes from all transactions
        const txHashes = this.txs.map(tx => tx.getHash());
        this.header.merkleRoot = calculateMerkleRoot(txHashes);
    }

    /**
     * Serialize the entire block (Header + Tx Count + Transactions)
     * (নেটওয়ার্কে অন্য নোডকে ব্লক পাঠানোর সময় এই ফাংশন ব্যবহার হয়)
     */
    serialize() {
        const headerBytes = this.header.serialize();
        
        // Calculate size required for transaction payload
        let txsPayloadSize = varIntSize(this.txs.length);
        const serializedTxs = this.txs.map(tx => tx.serialize());
        for (const txBytes of serializedTxs) {
            txsPayloadSize += txBytes.length;
        }

        const buffer = new Uint8Array(80 + txsPayloadSize);
        buffer.set(headerBytes, 0);

        const view = new DataView(buffer.buffer);
        let offset = 80;
        
        // Write tx count as VarInt
        offset = writeVarInt(view, offset, this.txs.length);
        
        // Write transactions
        for (const txBytes of serializedTxs) {
            buffer.set(txBytes, offset);
            offset += txBytes.length;
        }

        return buffer;
    }
}

module.exports = {
    calculateMerkleRoot,
    BlockHeader,
    Block
};
