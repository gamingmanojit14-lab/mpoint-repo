/**
 * MPOINT CORE - Binary Deserializer
 * ZERO external dependencies.
 * 
 * নেটওয়ার্ক থেকে আসা বাইনারি ডাটা (Tx এবং Block) পার্স করে আবার 
 * জাভাস্ক্রিপ্ট অবজেক্টে (TxIn, TxOut, Transaction, Block) কনভার্ট করার ইঞ্জিন।
 */

const { TxIn, TxOut, Transaction, bytesToHex, reverseBytes } = require('./tx.js');
const { BlockHeader, Block } = require('./block.js');

/**
 * Read a Variable Integer (VarInt) from a buffer
 * @param {Uint8Array} buffer 
 * @param {number} offset 
 * @returns {Object} { value: number, offset: number (new offset) }
 */
function readVarInt(buffer, offset) {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const prefix = view.getUint8(offset);
    
    if (prefix < 0xfd) {
        return { value: prefix, offset: offset + 1 };
    } else if (prefix === 0xfd) {
        return { value: view.getUint16(offset + 1, true), offset: offset + 3 };
    } else if (prefix === 0xfe) {
        return { value: view.getUint32(offset + 1, true), offset: offset + 5 };
    } else if (prefix === 0xff) {
        // Warning: JS limits precise integers to 53 bits. A block with > 9 quadrillion txs will fail here.
        // We cast BigUint64 to Number because JS arrays can't be sized by BigInt anyway.
        return { value: Number(view.getBigUint64(offset + 1, true)), offset: offset + 9 };
    }
}

/**
 * Parse a raw binary Transaction
 * @param {Uint8Array} buffer 
 * @param {number} startOffset 
 * @returns {Object} { tx: Transaction, offset: number }
 */
function parseTransaction(buffer, startOffset = 0) {
    let offset = startOffset;
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

    // 1. Version (4 bytes, Little-Endian)
    const version = view.getUint32(offset, true);
    offset += 4;

    // 2. Input Count
    const inCountData = readVarInt(buffer, offset);
    const inCount = inCountData.value;
    offset = inCountData.offset;

    // 3. Inputs
    const inputs = [];
    for (let i = 0; i < inCount; i++) {
        // txid (32 bytes, stored Little-Endian, display Big-Endian)
        const txidBytes = buffer.slice(offset, offset + 32);
        const prevTxid = bytesToHex(reverseBytes(txidBytes));
        offset += 32;

        const prevVout = view.getUint32(offset, true);
        offset += 4;

        const scriptLenData = readVarInt(buffer, offset);
        offset = scriptLenData.offset;

        const scriptSig = buffer.slice(offset, offset + scriptLenData.value);
        offset += scriptLenData.value;

        const sequence = view.getUint32(offset, true);
        offset += 4;

        inputs.push(new TxIn(prevTxid, prevVout, scriptSig, sequence));
    }

    // 4. Output Count
    const outCountData = readVarInt(buffer, offset);
    const outCount = outCountData.value;
    offset = outCountData.offset;

    // 5. Outputs
    const outputs = [];
    for (let i = 0; i < outCount; i++) {
        const value = view.getBigUint64(offset, true);
        offset += 8;

        const scriptLenData = readVarInt(buffer, offset);
        offset = scriptLenData.offset;

        const scriptPubKey = buffer.slice(offset, offset + scriptLenData.value);
        offset += scriptLenData.value;

        outputs.push(new TxOut(value, scriptPubKey));
    }

    // 6. Locktime (4 bytes)
    const locktime = view.getUint32(offset, true);
    offset += 4;

    const tx = new Transaction(version, inputs, outputs, locktime);
    return { tx, offset };
}

/**
 * Parse a raw binary Block
 * @param {Uint8Array} buffer 
 * @returns {Block}
 */
function parseBlock(buffer) {
    let offset = 0;
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

    // 1. Parse 80-byte Header
    const version = view.getUint32(offset, true); offset += 4;
    const prevBlockHash = buffer.slice(offset, offset + 32); offset += 32;
    const merkleRoot = buffer.slice(offset, offset + 32); offset += 32;
    const timestamp = view.getUint32(offset, true); offset += 4;
    const bits = view.getUint32(offset, true); offset += 4;
    const nonce = view.getUint32(offset, true); offset += 4;

    const header = new BlockHeader(version, prevBlockHash, merkleRoot, timestamp, bits, nonce);

    // 2. Parse Transaction Count
    const txCountData = readVarInt(buffer, offset);
    const txCount = txCountData.value;
    offset = txCountData.offset;

    // 3. Parse Transactions
    const txs = [];
    for (let i = 0; i < txCount; i++) {
        const parsedTx = parseTransaction(buffer, offset);
        txs.push(parsedTx.tx);
        offset = parsedTx.offset;
    }

    return new Block(header, txs);
}

module.exports = {
    readVarInt,
    parseTransaction,
    parseBlock
};
