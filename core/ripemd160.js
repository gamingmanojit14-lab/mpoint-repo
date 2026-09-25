/**
 * MPOINT CORE - RIPEMD-160 Implementation (Pure JavaScript)
 * ZERO external dependencies.
 * 
 * Bitcoin-style addresses require HASH160 (RIPEMD160 over SHA256).
 * ব্রাউজারের Web Crypto API-তে RIPEMD-160 সাপোর্ট নেই, তাই এটি স্ক্র্যাচ থেকে লেখা।
 */

const { sha256 } = require('./sha256.js');

// Shift amounts and message indices for the 5 rounds of the algorithm
const ZL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
];

const ZR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
];

const SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
];

const SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
];

// Nonlinear boolean functions (লজিক গেট অপারেশন)
const f1 = (x, y, z) => x ^ y ^ z;
const f2 = (x, y, z) => (x & y) | (~x & z);
const f3 = (x, y, z) => (x | ~y) ^ z;
const f4 = (x, y, z) => (x & z) | (y & ~z);
const f5 = (x, y, z) => x ^ (y | ~z);

// Left line constants (K) & Right line constants (K')
const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

// Bitwise left rotation (>>> 0 is used heavily to force 32-bit unsigned integers)
const rotl = (n, x) => ((x << n) | (x >>> (32 - n))) >>> 0;

/**
 * Core RIPEMD-160 hashing function
 * @param {Uint8Array} data 
 * @returns {Uint8Array} - 20-byte hash result
 */
function ripemd160(data) {
    const bitLen = data.length * 8;
    // Length in bytes: original + 1 (for 0x80) + 8 (for 64-bit length)
    const padLen = (data.length + 1 + 8) % 64;
    const padding = 64 - padLen;
    const totalLen = data.length + 1 + padding + 8; // Multiple of 64

    const buffer = new Uint8Array(totalLen);
    buffer.set(data);
    
    // Append the '1' bit (0x80)
    buffer[data.length] = 0x80;

    const dataView = new DataView(buffer.buffer);
    
    // WARNING: RIPEMD-160 uses LITTLE-ENDIAN for length formatting (SHA-256 uses Big-Endian)
    // Little-endian এ ডাটা সেভ করার জন্য setUint32(offset, value, true) ব্যবহার করা হয়েছে।
    const lowBits = bitLen >>> 0;
    const highBits = Math.floor(bitLen / 0x100000000); 
    dataView.setUint32(totalLen - 8, lowBits, true);  
    dataView.setUint32(totalLen - 4, highBits, true);

    // Initial state vectors
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;

    const X = new Uint32Array(16);

    for (let i = 0; i < totalLen; i += 64) {
        // Read 16 Little-Endian 32-bit words
        for (let j = 0; j < 16; j++) {
            X[j] = dataView.getUint32(i + j * 4, true);
        }

        let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
        let ar = h0, br = h1, cr = h2, dr = h3, er = h4;

        // 80 rounds total (5 phases of 16 rounds each)
        for (let j = 0; j < 80; j++) {
            const phase = Math.floor(j / 16);
            
            // Left line
            let fl = phase === 0 ? f1 : phase === 1 ? f2 : phase === 2 ? f3 : phase === 3 ? f4 : f5;
            let tl = (al + fl(bl, cl, dl) + X[ZL[j]] + KL[phase]) >>> 0;
            al = el;
            el = dl;
            dl = rotl(10, cl);
            cl = bl;
            bl = (rotl(SL[j], tl) + al) >>> 0;

            // Right line (phases are reversed)
            let fr = phase === 0 ? f5 : phase === 1 ? f4 : phase === 2 ? f3 : phase === 3 ? f2 : f1;
            let tr = (ar + fr(br, cr, dr) + X[ZR[j]] + KR[phase]) >>> 0;
            ar = er;
            er = dr;
            dr = rotl(10, cr);
            cr = br;
            br = (rotl(SR[j], tr) + ar) >>> 0;
        }

        // Combine left and right lines with current state
        let t = (h1 + cl + dr) >>> 0;
        h1 = (h2 + dl + er) >>> 0;
        h2 = (h3 + el + ar) >>> 0;
        h3 = (h4 + al + br) >>> 0;
        h4 = (h0 + bl + cr) >>> 0;
        h0 = t;
    }

    // Output final 20-byte hash in LITTLE-ENDIAN order
    const result = new Uint8Array(20);
    const resultView = new DataView(result.buffer);
    resultView.setUint32(0, h0, true);
    resultView.setUint32(4, h1, true);
    resultView.setUint32(8, h2, true);
    resultView.setUint32(12, h3, true);
    resultView.setUint32(16, h4, true);
    
    return result;
}

/**
 * Bitcoin/Mpoint Standard HASH160: RIPEMD160(SHA256(data))
 * পাবলিক-কী (Public Key) থেকে অ্যাড্রেস জেনারেট করার জন্য এই মেথড ব্যবহার হয়।
 * @param {Uint8Array} data 
 * @returns {Uint8Array} - 20-byte address payload
 */
function hash160(data) {
    return ripemd160(sha256(data));
}

module.exports = {
    ripemd160,
    hash160
};
