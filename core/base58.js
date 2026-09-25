/**
 * MPOINT CORE - Base58 & Base58Check Implementation (Pure JavaScript)
 * ZERO external dependencies. Browser and Node compatible.
 * 
 * Base58Check -এ ডাটার শেষে একটি চেকলিস্ট (Checksum) থাকে, যা টাইপিং মিস্টেক ধরতে সাহায্য করে।
 */

const { hash256 } = require('./sha256.js');

// Bitcoin/Mpoint Base58 Alphabet (0, O, l, I বাদ দেওয়া হয়েছে)
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Raw Base58 Encode
 * @param {Uint8Array} bytes 
 * @returns {string} Base58 encoded string
 */
function encode(bytes) {
    if (bytes.length === 0) return '';
    
    // 1. Count leading zero bytes (অ্যাড্রেসের শুরুতে '1' বসানোর জন্য)
    let zeroes = 0;
    while (zeroes < bytes.length && bytes[zeroes] === 0) zeroes++;
    
    // 2. Convert bytes to hex, then to BigInt (Browser-safe hex conversion)
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    let num = hex.length > 0 ? BigInt('0x' + hex) : 0n;
    
    // 3. Modulo 58 math
    let result = '';
    while (num > 0n) {
        let rem = Number(num % 58n);
        num = num / 58n;
        result = ALPHABET[rem] + result; // Prepend character
    }
    
    // 4. Append '1' for each leading zero byte
    for (let i = 0; i < zeroes; i++) {
        result = ALPHABET[0] + result;
    }
    
    return result;
}

/**
 * Raw Base58 Decode
 * @param {string} string 
 * @returns {Uint8Array}
 */
function decode(string) {
    if (string.length === 0) return new Uint8Array(0);
    
    // 1. Count leading '1's
    let zeroes = 0;
    while (zeroes < string.length && string[zeroes] === ALPHABET[0]) zeroes++;
    
    // 2. Decode string into BigInt
    let num = 0n;
    for (let char of string) {
        let val = ALPHABET.indexOf(char);
        if (val === -1) throw new Error(`Invalid Base58 character: ${char}`);
        num = num * 58n + BigInt(val);
    }
    
    // 3. Convert BigInt back to bytes (Browser-safe)
    let hex = num.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    
    const numBytes = (hex === '00' && num === 0n) 
        ? new Uint8Array(0) 
        : new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    
    // 4. Restore leading zero bytes
    const result = new Uint8Array(zeroes + numBytes.length);
    result.set(numBytes, zeroes);
    
    return result;
}

/**
 * Base58Check Encode (Payload + Version + Checksum)
 * @param {Uint8Array} payloadBytes - e.g., 20-byte HASH160
 * @param {number} versionByte - Network version (Mpoint = 0x1C)
 * @returns {string} Final Wallet Address
 */
function encodeCheck(payloadBytes, versionByte) {
    // 1. Create buffer with Version Byte + Payload
    const buffer = new Uint8Array(1 + payloadBytes.length);
    buffer[0] = versionByte;
    buffer.set(payloadBytes, 1);
    
    // 2. Compute 4-byte Checksum: HASH256(buffer)
    const checksum = hash256(buffer).slice(0, 4);
    
    // 3. Append Checksum and Encode
    const finalBuffer = new Uint8Array(buffer.length + 4);
    finalBuffer.set(buffer, 0);
    finalBuffer.set(checksum, buffer.length);
    
    return encode(finalBuffer);
}

/**
 * Base58Check Decode and Validate
 * @param {string} addressStr 
 * @returns {Object} { version: number, payload: Uint8Array }
 */
function decodeCheck(addressStr) {
    const bytes = decode(addressStr);
    
    if (bytes.length < 5) {
        throw new Error("Invalid Base58Check data: too short (অ্যাড্রেস খুব ছোট)");
    }
    
    // Extract payload and checksum
    const data = bytes.slice(0, -4);
    const checksum = bytes.slice(-4);
    
    // Verify checksum
    const expectedChecksum = hash256(data).slice(0, 4);
    for (let i = 0; i < 4; i++) {
        if (checksum[i] !== expectedChecksum[i]) {
            throw new Error("Base58Check Checksum failed. (অ্যাড্রেস ভুল বা টেম্পার করা হয়েছে)");
        }
    }
    
    return {
        version: data[0],
        payload: data.slice(1)
    };
}

module.exports = {
    encode,
    decode,
    encodeCheck,
    decodeCheck
};
