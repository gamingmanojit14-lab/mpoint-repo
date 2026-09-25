/**
 * MPOINT CORE - Consensus & Proof-of-Work Rules
 * ZERO external dependencies.
 * 
 * ব্লক মাইনিংয়ের নিয়ম, রিওয়ার্ড (Halving) এবং কাঠিন্য (Difficulty) ঠিক করার গাণিতিক লজিক।
 */

const { bytesToBigInt } = require('./secp256k1.js'); // Re-using the BigInt converter

// --- Consensus Constants (Master Spec §3) ---

const TARGET_BLOCK_TIME = 120; // 2 minutes (in seconds)
const DIFFICULTY_ADJUSTMENT_INTERVAL = 2016; // Retarget every 2016 blocks
const TARGET_TIMESPAN = TARGET_BLOCK_TIME * DIFFICULTY_ADJUSTMENT_INTERVAL; // 241,920 seconds

const HALVING_INTERVAL = 1050000; // Halve every 1.05M blocks (approx 4 years)
const INITIAL_REWARD = 5000000000n; // 50 MPT = 5,000,000,000 mptoshi

// Maximum Target (Genesis Difficulty) - 0x1d00ffff
// The highest possible hash target. If the target goes above this, it is clamped here.
const MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000n;

// --- Compact Target (Bits) Encoding & Decoding ---
// Bitcoin stores 256-bit targets in a compressed 32-bit format called "bits".
// Formula: value = mantissa * 256^(exponent - 3)

/**
 * Decode 32-bit compact 'bits' into a 256-bit BigInt target
 * @param {number} bits - 32-bit unsigned integer
 * @returns {BigInt} 256-bit target
 */
function bitsToTarget(bits) {
    const exponent = bits >>> 24;
    let mantissa = bits & 0x00ffffff;

    // Handle negative numbers (if sign bit is set, technically invalid in PoW but part of standard)
    if (mantissa & 0x00800000) {
        mantissa = -1 * (mantissa & 0x007fffff);
    }

    if (exponent <= 3) {
        return BigInt(mantissa) >> BigInt(8 * (3 - exponent));
    } else {
        return BigInt(mantissa) << BigInt(8 * (exponent - 3));
    }
}

/**
 * Encode a 256-bit BigInt target into 32-bit compact 'bits'
 * @param {BigInt} target - 256-bit BigInt
 * @returns {number} 32-bit unsigned integer (bits)
 */
function targetToBits(target) {
    if (target <= 0n) return 0;
    
    let hex = target.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    
    let exponent = hex.length / 2;
    let mantissaHex = hex.substring(0, 6).padEnd(6, '0');
    let mantissa = parseInt(mantissaHex, 16);
    
    // If mantissa has sign bit set, we must shift exponent right to fit a leading zero byte
    if (mantissa & 0x00800000) {
        mantissa >>= 8;
        exponent++;
    }
    
    return ((exponent << 24) | mantissa) >>> 0; // Force unsigned 32-bit
}

// --- Consensus Rules ---

/**
 * Check if a block hash satisfies its stated difficulty target
 * (ব্লকের হ্যাশ কি টার্গেটের চেয়ে ছোট? যদি হ্যাঁ হয়, তবে PoW সফল)
 * 
 * @param {Uint8Array} blockHash - 32-byte hash (Little-Endian)
 * @param {number} bits - Compact difficulty target
 * @returns {boolean}
 */
function checkProofOfWork(blockHash, bits) {
    // Reverse hash to Big-Endian for BigInt comparison
    const reversedHash = new Uint8Array(blockHash.length);
    for (let i = 0; i < blockHash.length; i++) {
        reversedHash[i] = blockHash[blockHash.length - 1 - i];
    }
    
    const hashValue = bytesToBigInt(reversedHash);
    const targetValue = bitsToTarget(bits);
    
    if (targetValue <= 0n || targetValue > MAX_TARGET) return false;
    
    return hashValue <= targetValue;
}

/**
 * Calculate the Block Reward based on current height (Halving logic)
 * @param {number} blockHeight - Current height of the blockchain
 * @returns {BigInt} Reward in mptoshi
 */
function getBlockReward(blockHeight) {
    const halvings = Math.floor(blockHeight / HALVING_INTERVAL);
    
    // Force zero reward after 64 halvings (Bitcoin limits right-shifts to 64)
    if (halvings >= 64) return 0n;
    
    // Right shift (>>n) is mathematically equivalent to dividing by 2^n
    return INITIAL_REWARD >> BigInt(halvings);
}

/**
 * Calculate the next difficulty target (Retargeting Algorithm)
 * 
 * @param {number} previousBits - The 'bits' value of the last block
 * @param {number} actualTimespan - Time taken to mine the last 2016 blocks (in seconds)
 * @returns {number} The new 'bits' value
 */
function calculateNextWorkRequired(previousBits, actualTimespan) {
    let timespan = actualTimespan;
    
    // Clamp the adjustment to prevent extreme difficulty shocks (Max 4x, Min 0.25x)
    if (timespan < TARGET_TIMESPAN / 4) timespan = TARGET_TIMESPAN / 4;
    if (timespan > TARGET_TIMESPAN * 4) timespan = TARGET_TIMESPAN * 4;
    
    const oldTarget = bitsToTarget(previousBits);
    
    // newTarget = (oldTarget * timespan) / targetTimespan
    let newTarget = (oldTarget * BigInt(timespan)) / BigInt(TARGET_TIMESPAN);
    
    if (newTarget > MAX_TARGET) {
        newTarget = MAX_TARGET;
    }
    
    return targetToBits(newTarget);
}

module.exports = {
    TARGET_BLOCK_TIME,
    DIFFICULTY_ADJUSTMENT_INTERVAL,
    MAX_TARGET,
    bitsToTarget,
    targetToBits,
    checkProofOfWork,
    getBlockReward,
    calculateNextWorkRequired
};
