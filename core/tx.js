/**
 * MPOINT CORE - Transaction Model & Byte-Serialization
 * ZERO external dependencies. Browser & Node.js compatible.
 * 
 * বিটকয়েনের হুবহু (bit-for-bit) বাইনারি সিরিয়ালাইজেশন প্রটোকল ব্যবহার করা হয়েছে।
 * Little-Endian ফরম্যাটে সংখ্যাগুলো মেমোরিতে লেখা হয়।
 */

const { hash256 } = require('./sha256.js');

// --- Helper Utilities (বাইনারি ডাটা ম্যানেজমেন্ট) ---

// Reverse bytes (Bitcoin TXIDs are stored in Little-Endian but displayed in Big-Endian)
function reverseBytes(bytes) {
    const reversed = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        reversed[i] = bytes[bytes.length - 1 - i];
    }
    return reversed;
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- Variable Integer (VarInt) Encoding ---
// 블কচেইনে স্পেস বাঁচানোর জন্য VarInt ব্যবহার করা হয়। ছোট সংখ্যার জন্য ১ বাইট, বড়র জন্য ৩, ৫ বা ৯ বাইট।

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

// --- Transaction Classes ---

class TxIn {
    /**
     * @param {string} prevTxid - Hex string of the previous transaction ID (Big-Endian format)
     * @param {number} prevVout - Output index in the previous transaction
     * @param {Uint8Array} scriptSig - Unlocking script bytes
     * @param {number} sequence - Sequence number (Usually 0xFFFFFFFF)
     */
    constructor(prevTxid, prevVout, scriptSig = new Uint8Array(0), sequence = 0xFFFFFFFF) {
        this.prevTxid = prevTxid; // Stored as standard display hex
        this.prevVout = prevVout;
        this.scriptSig = scriptSig;
        this.sequence = sequence;
    }

    getSize() {
        return 32 + 4 + varIntSize(this.scriptSig.length) + this.scriptSig.length + 4;
    }
}

class TxOut {
    /**
     * @param {BigInt} value - Amount in mptoshi (uint64)
     * @param {Uint8Array} scriptPubKey - Locking script bytes
     */
    constructor(value, scriptPubKey) {
        this.value = BigInt(value); // Force BigInt for 64-bit precision
        this.scriptPubKey = scriptPubKey;
    }

    getSize() {
        return 8 + varIntSize(this.scriptPubKey.length) + this.scriptPubKey.length;
    }
}

class Transaction {
    constructor(version = 1, inputs = [], outputs = [], locktime = 0) {
        this.version = version;
        this.inputs = inputs;
        this.outputs = outputs;
        this.locktime = locktime;
    }

    /**
     * Calculate total serialized size of the transaction in bytes
     */
    getSize() {
        let size = 4; // version (4 bytes)
        size += varIntSize(this.inputs.length);
        for (const input of this.inputs) size += input.getSize();
        size += varIntSize(this.outputs.length);
        for (const output of this.outputs) size += output.getSize();
        size += 4; // locktime (4 bytes)
        return size;
    }

    /**
     * Serialize the transaction into a binary Uint8Array
     * (ট্রানজেকশনকে বাইনারিতে কনভার্ট করা)
     */
    serialize() {
        const buffer = new Uint8Array(this.getSize());
        const view = new DataView(buffer.buffer);
        let offset = 0;

        // 1. Version (4 bytes, Little-Endian)
        view.setUint32(offset, this.version, true);
        offset += 4;

        // 2. Input Count (VarInt)
        offset = writeVarInt(view, offset, this.inputs.length);

        // 3. Inputs
        for (const input of this.inputs) {
            // prevTxid must be serialized in Little-Endian (reversed from display hex)
            const txidBytes = reverseBytes(hexToBytes(input.prevTxid));
            buffer.set(txidBytes, offset);
            offset += 32;

            view.setUint32(offset, input.prevVout, true);
            offset += 4;

            offset = writeVarInt(view, offset, input.scriptSig.length);
            buffer.set(input.scriptSig, offset);
            offset += input.scriptSig.length;

            view.setUint32(offset, input.sequence, true);
            offset += 4;
        }

        // 4. Output Count (VarInt)
        offset = writeVarInt(view, offset, this.outputs.length);

        // 5. Outputs
        for (const output of this.outputs) {
            view.setBigUint64(offset, output.value, true); // 8 bytes, LE
            offset += 8;

            offset = writeVarInt(view, offset, output.scriptPubKey.length);
            buffer.set(output.scriptPubKey, offset);
            offset += output.scriptPubKey.length;
        }

        // 6. Locktime (4 bytes, Little-Endian)
        view.setUint32(offset, this.locktime, true);
        offset += 4;

        return buffer;
    }

    /**
     * Get Transaction Hash (Used for internal block structures)
     * @returns {Uint8Array} 32-byte hash (Little-Endian array)
     */
    getHash() {
        return hash256(this.serialize());
    }

    /**
     * Get Transaction ID (Standard Display Format)
     * @returns {string} Big-Endian Hex String
     */
    getId() {
        // TXIDs are universally displayed as reversed (Big-Endian) hex strings
        return bytesToHex(reverseBytes(this.getHash()));
    }

    /**
     * Generate SIGHASH_ALL for a specific input
     * (সিগনেচার তৈরি করার আগে ট্রানজেকশনের ডাটা হ্যাশ করা হয়)
     * 
     * @param {number} inputIndex - Index of the input being signed
     * @param {Uint8Array} prevScriptPubKey - The locking script of the UTXO being spent
     * @returns {Uint8Array} 32-byte message hash ready for ECDSA signing
     */
    getSigHash(inputIndex, prevScriptPubKey) {
        // Clone the transaction so we don't modify the original
        const clone = new Transaction(
            this.version,
            this.inputs.map(i => new TxIn(i.prevTxid, i.prevVout, new Uint8Array(0), i.sequence)),
            this.outputs, // Outputs remain unchanged for SIGHASH_ALL
            this.locktime
        );

        // Standard Protocol: Temporarily place the prev_out scriptPubKey into the active input
        clone.inputs[inputIndex].scriptSig = prevScriptPubKey;

        // Serialize the cloned transaction
        const serializedTx = clone.serialize();

        // Append SIGHASH_ALL (0x01000000 in Little-Endian) - 4 bytes
        const buffer = new Uint8Array(serializedTx.length + 4);
        buffer.set(serializedTx, 0);
        
        const view = new DataView(buffer.buffer);
        view.setUint32(serializedTx.length, 1, true); // SIGHASH_ALL = 1

        // Hash256 the entire payload
        return hash256(buffer);
    }
}

module.exports = {
    TxIn,
    TxOut,
    Transaction,
    reverseBytes,
    hexToBytes,
    bytesToHex
};
