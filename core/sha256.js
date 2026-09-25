/**
 * MPOINT CORE - SHA-256 Implementation (Pure JavaScript)
 * ZERO external dependencies. (কোনো থার্ড-পার্টি লাইব্রেরি নেই)
 * 
 * This module processes Uint8Array inputs and returns Uint8Array hashes.
 * ব্লকচেইনে বাইনারি ডাটা নিয়ে কাজ হয়, তাই String এর বদলে Uint8Array ব্যবহার করা হয়েছে।
 */

// SHA-256 Constants (NIST standard) - প্রথম 64টি প্রাইম নাম্বারের cube root এর ফ্র্যাকশনাল পার্ট
const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

// Initial Hash Values - প্রথম 8টি প্রাইম নাম্বারের square root এর ফ্র্যাকশনাল পার্ট
const H_INIT = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

// Bitwise right rotation (JavaScript -এ bitwise operation 32-bit signed integer-এ হয়, তাই >>> ব্যবহার করতে হবে)
const rotr = (n, x) => (x >>> n) | (x << (32 - n));

/**
 * Core SHA-256 hashing function
 * @param {Uint8Array} data - Input data (যেমন ব্লক হেডার বা ট্রানজেকশন)
 * @returns {Uint8Array} - 32-byte hash result
 */
function sha256(data) {
    // 1. Padding preparation (ডাটা প্যাডিং শুরু হচ্ছে)
    const bitLen = data.length * 8;
    // Length is original length in bits + 1 (for the 0x80 byte) + 8 (for 64-bit length)
    const padLen = (data.length + 1 + 8) % 64;
    const padding = 64 - padLen;
    const totalLen = data.length + 1 + padding + 8; // Must be multiple of 64 bytes

    const buffer = new Uint8Array(totalLen);
    buffer.set(data);
    
    // Append the '1' bit (0x80)
    buffer[data.length] = 0x80;

    // Append 64-bit length in bits at the very end (Big-Endian format)
    const dataView = new DataView(buffer.buffer);
    // JavaScript can only safely do bitwise math up to 32 bits, so we split the 64-bit length
    const highBits = Math.floor(bitLen / 0x100000000); 
    const lowBits = bitLen >>> 0;
    dataView.setUint32(totalLen - 8, highBits, false);
    dataView.setUint32(totalLen - 4, lowBits, false);

    // 2. Initialize hash values (H0 থেকে H7 পর্যন্ত)
    const H = new Uint32Array(H_INIT);
    const W = new Uint32Array(64);

    // 3. Process the message in successive 512-bit (64-byte) chunks
    for (let chunkStart = 0; chunkStart < totalLen; chunkStart += 64) {
        // Message schedule array W তৈরি করা হচ্ছে
        for (let i = 0; i < 16; i++) {
            W[i] = dataView.getUint32(chunkStart + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const w15 = W[i - 15];
            const s0 = rotr(7, w15) ^ rotr(18, w15) ^ (w15 >>> 3);
            const w2 = W[i - 2];
            const s1 = rotr(17, w2) ^ rotr(19, w2) ^ (w2 >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
        }

        // Working variables (chunk-এর জন্য লোকাল ভেরিয়েবল)
        let [a, b, c, d, e, f, g, h] = H;

        // Compression function (মেইন কম্প্রেশন লুপ)
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
            const ch = (e & f) ^ ((~e) & g);
            const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
            const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;

            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }

        // Add the compressed chunk to the current hash value
        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }

    // 4. Produce the final hash as Uint8Array (বিগ-এন্ডিয়ান ফরম্যাটে কনভার্ট করা)
    const result = new Uint8Array(32);
    const resultView = new DataView(result.buffer);
    for (let i = 0; i < 8; i++) {
        resultView.setUint32(i * 4, H[i], false);
    }
    return result;
}

/**
 * Double SHA-256: Bitcoin and Mpoint use SHA256(SHA256(data)) for txids and block hashes.
 * ব্লকচেইনের নিরাপত্তার জন্য ডাটাকে দুবার হ্যাশ করা হয়।
 * @param {Uint8Array} data 
 * @returns {Uint8Array}
 */
function hash256(data) {
    return sha256(sha256(data));
}

// Export for Node.js (CommonJS) - ব্রাউজারে ব্যবহার করার সময় মডিউল ইম্পোর্ট করা যাবে
module.exports = {
    sha256,
    hash256
};
