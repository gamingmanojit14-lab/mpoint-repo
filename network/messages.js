/**
 * MPOINT NETWORK - P2P Wire Protocol Messages
 * ZERO external dependencies.
 * 
 * বিটকয়েনের P2P ওয়্যার প্রটোকল (Wire Protocol) হুবহু ফলো করা হয়েছে। 
 * নেটওয়ার্কে পাঠানো প্রতিটি ডেটা এই নির্দিষ্ট ফরম্যাটে এনকোড করা হয়।
 */

const { hash256 } = require('../core/sha256.js');

// Mpoint Mainnet Magic Bytes ('M', 'P', 'T', '1')
const MAGIC_BYTES = new Uint8Array([0x4d, 0x50, 0x54, 0x31]);

/**
 * Encode a message into the binary wire format
 * @param {string} commandStr - Command name (max 12 chars, e.g., 'version', 'tx')
 * @param {Uint8Array} payload - The binary payload (optional)
 * @returns {Uint8Array} Fully assembled network message
 */
function encodeMessage(commandStr, payload = new Uint8Array(0)) {
    if (commandStr.length > 12) throw new Error("Command string exceeds 12 bytes");

    const buffer = new Uint8Array(24 + payload.length);
    const view = new DataView(buffer.buffer);

    // 1. Magic Bytes (4 bytes)
    buffer.set(MAGIC_BYTES, 0);

    // 2. Command String (12 bytes, ASCII, null padded)
    for (let i = 0; i < 12; i++) {
        buffer[4 + i] = i < commandStr.length ? commandStr.charCodeAt(i) : 0x00;
    }

    // 3. Payload Length (4 bytes, Little-Endian)
    view.setUint32(16, payload.length, true);

    // 4. Checksum (4 bytes) -> First 4 bytes of HASH256(payload)
    // Note: Even if payload is empty, we must hash the empty array
    const checksum = hash256(payload).slice(0, 4);
    buffer.set(checksum, 20);

    // 5. Payload Data
    if (payload.length > 0) {
        buffer.set(payload, 24);
    }

    return buffer;
}

/**
 * Decode a binary buffer from the network into a message object.
 * (TCP স্ট্রিম থেকে ডাটা এলে তা পার্স করার ফাংশন)
 * 
 * @param {Uint8Array} buffer - The raw binary buffer from the socket
 * @returns {Object|null} { command, payload, messageLength } or null if incomplete
 */
function decodeMessage(buffer) {
    // Header is exactly 24 bytes. If we don't have 24 bytes, wait for more TCP packets.
    if (buffer.length < 24) return null;

    // 1. Verify Magic Bytes
    for (let i = 0; i < 4; i++) {
        if (buffer[i] !== MAGIC_BYTES[i]) {
            throw new Error(`Invalid Magic Bytes. Expected ${MAGIC_BYTES}, got ${buffer.slice(0,4)}`);
        }
    }

    // 2. Extract Command String (Stop at first null byte 0x00)
    let command = '';
    for (let i = 4; i < 16; i++) {
        if (buffer[i] === 0x00) break;
        command += String.fromCharCode(buffer[i]);
    }

    // 3. Extract Payload Length
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const payloadLength = view.getUint32(16, true); // Little-Endian

    // Check if the full payload has arrived in the TCP stream
    const totalMessageLength = 24 + payloadLength;
    if (buffer.length < totalMessageLength) {
        return null; // TCP fragmentation: Need to wait for more data chunks
    }

    // 4. Extract Payload and Verify Checksum
    const payload = buffer.slice(24, totalMessageLength);
    const expectedChecksum = buffer.slice(20, 24);
    const actualChecksum = hash256(payload).slice(0, 4);

    for (let i = 0; i < 4; i++) {
        if (expectedChecksum[i] !== actualChecksum[i]) {
            throw new Error(`Payload checksum failed for command: ${command}. (ডাটা করাপ্ট হয়েছে)`);
        }
    }

    return {
        command,
        payload,
        messageLength: totalMessageLength // Used to slice the TCP buffer
    };
}

module.exports = {
    MAGIC_BYTES,
    encodeMessage,
    decodeMessage
};
