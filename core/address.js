/**
 * MPOINT CORE - Address Derivation
 * 
 * পাবলিক-কী থেকে Mpoint অ্যাড্রেস জেনারেট করার লজিক।
 */

const { hash160 } = require('./ripemd160.js');
const { encodeCheck, decodeCheck } = require('./base58.js');
const { getPublicKey } = require('./secp256k1.js');

// Mpoint Mainnet Version Byte (0x1C) - As defined in Master Spec §1
const MPOINT_VERSION_MAINNET = 0x1C;

/**
 * Derive Wallet Address from Public Key
 * @param {Uint8Array} pubKeyBytes - 33-byte (compressed) or 65-byte public key
 * @returns {string} Base58Check encoded address (e.g., M...)
 */
function pubKeyToAddress(pubKeyBytes) {
    // 1. Hash the public key to 20 bytes: RIPEMD160(SHA256(PubKey))
    const payload = hash160(pubKeyBytes);
    
    // 2. Encode with version byte and checksum
    return encodeCheck(payload, MPOINT_VERSION_MAINNET);
}

/**
 * Derive Wallet Address directly from Private Key (Helper function)
 * @param {Uint8Array} privKeyBytes - 32-byte private key
 * @returns {string} Wallet Address
 */
function privateKeyToAddress(privKeyBytes) {
    // We strictly use compressed public keys for Mpoint as they save space on the blockchain
    const pubKey = getPublicKey(privKeyBytes, true);
    return pubKeyToAddress(pubKey);
}

/**
 * Validate if a given string is a correct Mpoint Mainnet address
 * @param {string} addressStr 
 * @returns {boolean} True if valid
 */
function validateAddress(addressStr) {
    try {
        const { version, payload } = decodeCheck(addressStr);
        // Payload must be exactly 20 bytes (Hash160 output length)
        return version === MPOINT_VERSION_MAINNET && payload.length === 20;
    } catch (e) {
        // Checksum failure or invalid format
        return false;
    }
}

module.exports = {
    MPOINT_VERSION_MAINNET,
    pubKeyToAddress,
    privateKeyToAddress,
    validateAddress
};
