/**
 * MPOINT CORE - secp256k1 Elliptic Curve Implementation (Pure JavaScript)
 * ZERO external dependencies. Uses ES2020 BigInt for high-precision math.
 * 
 * বিটকয়েন এবং এমপয়েন্ট উভয়েই secp256k1 কার্ভ ব্যবহার করে। 
 * ব্রাউজারে এটি নেটিভলি সাপোর্ট না থাকায়, এখানে গাণিতিক সূত্র ব্যবহার করে স্ক্র্যাচ থেকে তৈরি করা হয়েছে।
 */

// Curve Constants (secp256k1 parameter specification)
// y^2 = x^3 + 7 over F_p
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn; // Prime field
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n; // Order of base point
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n; // Generator X
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n; // Generator Y

// --- Helper Functions (গাণিতিক সাহায্যকারী ফাংশন) ---

// Modulo that handles negative numbers correctly (জাভাস্ক্রিপ্টে % নেগেটিভ রেজাল্ট দিতে পারে)
const mod = (a, b) => ((a % b) + b) % b;

// Modular exponentiation (modPow) - Fermat's Little Theorem এর জন্য লাগে
function modPow(base, exp, modulus) {
    let res = 1n;
    let b = mod(base, modulus);
    let e = exp;
    while (e > 0n) {
        if (e % 2n === 1n) res = mod(res * b, modulus);
        b = mod(b * b, modulus);
        e /= 2n;
    }
    return res;
}

// Modular Inverse using Fermat's Little Theorem (a^(p-2) mod p)
// ইনভার্স বের করার জন্য এটি সবচেয়ে সহজ এবং নিরাপদ পদ্ধতি
const modInverse = (n, modulus) => modPow(n, modulus - 2n, modulus);

// Convert Uint8Array to BigInt
const bytesToBigInt = (bytes) => BigInt('0x' + Buffer.from(bytes).toString('hex'));

// Convert BigInt to 32-byte Uint8Array
function bigIntToBytes(num) {
    let hex = num.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const pad = 64 - hex.length;
    if (pad > 0) hex = '0'.repeat(pad) + hex;
    return new Uint8Array(Buffer.from(hex, 'hex'));
}

// Secure Random Generator (ব্রাউজার এবং নোড জেএস উভয়ের জন্য)
function getSecureRandomBytes(len) {
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
        return globalThis.crypto.getRandomValues(new Uint8Array(len));
    } else if (typeof require !== 'undefined') {
        return require('crypto').randomBytes(len);
    }
    throw new Error("No secure random environment found.");
}

// --- Elliptic Curve Point Arithmetic (কার্ভের উপর বিন্দু যোগ এবং গুণ) ---

// Point addition (P1 + P2)
function pointAdd(p1, p2) {
    if (p1 === null) return p2;
    if (p2 === null) return p1;

    if (p1.x === p2.x && p1.y !== p2.y) return null; // Point at infinity

    let lam;
    if (p1.x === p2.x && p1.y === p2.y) {
        // Point doubling (একই পয়েন্ট দুইবার যোগ করা)
        lam = mod(3n * modPow(p1.x, 2n, P) * modInverse(2n * p1.y, P), P);
    } else {
        // Standard addition
        lam = mod((p2.y - p1.y) * modInverse(p2.x - p1.x, P), P);
    }

    const x3 = mod(modPow(lam, 2n, P) - p1.x - p2.x, P);
    const y3 = mod(lam * (p1.x - x3) - p1.y, P);
    
    return { x: x3, y: y3 };
}

// Scalar point multiplication (Double-and-add algorithm)
function pointMultiply(point, scalar) {
    let result = null;
    let addend = point;
    let k = scalar;

    while (k > 0n) {
        if (k & 1n) result = pointAdd(result, addend);
        addend = pointAdd(addend, addend);
        k >>= 1n; // Shift right by 1 bit
    }
    return result;
}

// --- Public APIs (কীপ্যায়ার এবং সিগনেচার ফাংশন) ---

/**
 * Generate a new random private key
 * @returns {Uint8Array} 32-byte private key
 */
function generatePrivateKey() {
    let priv;
    do {
        priv = bytesToBigInt(getSecureRandomBytes(32));
    } while (priv <= 0n || priv >= N); // Must be strictly between 0 and N
    return bigIntToBytes(priv);
}

/**
 * Get Public Key from Private Key
 * @param {Uint8Array} privateKeyBytes 
 * @param {boolean} compressed - Default true (Mpoint uses compressed keys by default)
 * @returns {Uint8Array} 33-byte (compressed) or 65-byte (uncompressed) public key
 */
function getPublicKey(privateKeyBytes, compressed = true) {
    const priv = bytesToBigInt(privateKeyBytes);
    if (priv <= 0n || priv >= N) throw new Error("Invalid private key");

    const G = { x: Gx, y: Gy };
    const pubPoint = pointMultiply(G, priv);

    const xBytes = bigIntToBytes(pubPoint.x);
    if (compressed) {
        // Compressed: 0x02 if y is even, 0x03 if y is odd (জোড় হলে 02, বিজোড় হলে 03)
        const prefix = pubPoint.y % 2n === 0n ? 0x02 : 0x03;
        const pubKey = new Uint8Array(33);
        pubKey[0] = prefix;
        pubKey.set(xBytes, 1);
        return pubKey;
    } else {
        // Uncompressed: 0x04 + X + Y
        const yBytes = bigIntToBytes(pubPoint.y);
        const pubKey = new Uint8Array(65);
        pubKey[0] = 0x04;
        pubKey.set(xBytes, 1);
        pubKey.set(yBytes, 33);
        return pubKey;
    }
}

/**
 * ECDSA Sign (Bitcoin compatible with strict Low-S rule)
 * @param {Uint8Array} msgHash - 32-byte hash of the transaction/message
 * @param {Uint8Array} privateKey - 32-byte private key
 * @returns {Object} { r: Uint8Array, s: Uint8Array } - Raw signature parts
 */
function sign(msgHash, privateKey) {
    const z = bytesToBigInt(msgHash);
    const priv = bytesToBigInt(privateKey);
    const G = { x: Gx, y: Gy };
    
    let r = 0n, s = 0n;
    
    while (s === 0n) {
        // Generate a random nonce k (In production RFC6979 deterministic k is preferred, but secure random is acceptable for v1)
        let k;
        do {
            k = bytesToBigInt(getSecureRandomBytes(32));
        } while (k <= 0n || k >= N);

        const point = pointMultiply(G, k);
        r = mod(point.x, N);
        
        if (r === 0n) continue;

        s = mod(modInverse(k, N) * (z + r * priv), N);
        
        // Strict Low-S Rule (BIP 62 / BIP 146): Network will reject high-S signatures
        if (s > N / 2n) {
            s = N - s;
        }
    }
    
    return { r: bigIntToBytes(r), s: bigIntToBytes(s) };
}

/**
 * Recover full public point from compressed/uncompressed bytes
 * (সিগনেচার ভেরিফাই করার আগে পাবলিক-কীকে ডিকোড করতে হয়)
 */
function decodePublicKey(pubKeyBytes) {
    const prefix = pubKeyBytes[0];
    const x = bytesToBigInt(pubKeyBytes.slice(1, 33));

    if (prefix === 0x04) {
        const y = bytesToBigInt(pubKeyBytes.slice(33, 65));
        return { x, y };
    } else if (prefix === 0x02 || prefix === 0x03) {
        // y^2 = x^3 + 7
        const ySquared = mod(modPow(x, 3n, P) + 7n, P);
        // p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) mod p
        let y = modPow(ySquared, (P + 1n) / 4n, P);
        
        const isYEven = (y % 2n === 0n);
        const expectedEven = (prefix === 0x02);
        
        if (isYEven !== expectedEven) {
            y = mod(P - y, P);
        }
        return { x, y };
    }
    throw new Error("Invalid public key prefix");
}

/**
 * ECDSA Verify
 * @param {Uint8Array} msgHash - 32-byte hash
 * @param {Uint8Array} pubKeyBytes - 33-byte or 65-byte public key
 * @param {Object} signature - { r: Uint8Array, s: Uint8Array }
 * @returns {boolean} True if signature is valid (সিগনেচার সঠিক হলে true রিটার্ন করবে)
 */
function verify(msgHash, pubKeyBytes, signature) {
    const z = bytesToBigInt(msgHash);
    const r = bytesToBigInt(signature.r);
    const s = bytesToBigInt(signature.s);
    
    if (r <= 0n || r >= N || s <= 0n || s >= N) return false;

    const pubPoint = decodePublicKey(pubKeyBytes);
    
    const w = modInverse(s, N);
    const u1 = mod(z * w, N);
    const u2 = mod(r * w, N);
    
    const G = { x: Gx, y: Gy };
    const p1 = pointMultiply(G, u1);
    const p2 = pointMultiply(pubPoint, u2);
    
    const resultPoint = pointAdd(p1, p2);
    
    if (resultPoint === null) return false;
    
    return mod(resultPoint.x, N) === r;
}

module.exports = {
    generatePrivateKey,
    getPublicKey,
    sign,
    verify,
    bytesToBigInt // Exported for test utilities
};
