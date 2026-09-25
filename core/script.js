/**
 * MPOINT CORE - Script Interpreter (Subset of Bitcoin Script)
 * ZERO external dependencies.
 * 
 * বিটকয়েনের মতো এমপয়েন্টেও UTXO লক এবং আনলক করার জন্য স্ক্রিপ্ট ইঞ্জিন ব্যবহার করা হয়।
 * এটি একটি Stack-based (LIFO) ইঞ্জিন, যা শুধু P2PKH সাবসেট সাপোর্ট করে।
 */

const { hash160 } = require('./ripemd160.js');

// Supported Opcodes (Hex values exactly match Bitcoin Core)
const OP = {
    DUP: 0x76,           // Duplicate top stack item
    EQUAL: 0x87,         // Check if top two items are equal
    EQUALVERIFY: 0x88,   // Check equality, fail immediately if not equal
    HASH160: 0xa9,       // Hash top item with RIPEMD160(SHA256(x))
    CHECKSIG: 0xac,      // Verify ECDSA signature
    RETURN: 0x6a         // Mark output invalid/unspendable (used for arbitrary data)
};

/**
 * Helper to compare two Uint8Arrays
 * @param {Uint8Array} a 
 * @param {Uint8Array} b 
 * @returns {boolean}
 */
function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Builds a Pay-To-Public-Key-Hash (P2PKH) Locking Script
 * Format: OP_DUP OP_HASH160 <20-byte pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 * (যাকে টাকা পাঠানো হচ্ছে, তার অ্যাড্রেসের হ্যাশ দিয়ে লক করা হয়)
 * 
 * @param {Uint8Array} pubKeyHash - 20-byte HASH160 of recipient's public key
 * @returns {Uint8Array} Locking Script bytes
 */
function createP2PKHLockScript(pubKeyHash) {
    if (pubKeyHash.length !== 20) throw new Error("pubKeyHash must be 20 bytes");
    const script = new Uint8Array(25);
    script[0] = OP.DUP;
    script[1] = OP.HASH160;
    script[2] = 20; // OP_PUSHBYTES_20 (0x14)
    script.set(pubKeyHash, 3);
    script[23] = OP.EQUALVERIFY;
    script[24] = OP.CHECKSIG;
    return script;
}

/**
 * Builds a P2PKH Unlocking Script
 * Format: <sig_length> <signature> <pubkey_length> <pubkey>
 * (খরচ করার সময় নিজের সিগনেচার এবং পাবলিক-কী দিয়ে আনলক করতে হয়)
 * 
 * @param {Uint8Array} signature - Raw signature bytes (including SIGHASH flag)
 * @param {Uint8Array} pubKey - 33-byte compressed public key
 * @returns {Uint8Array} Unlocking Script bytes
 */
function createP2PKHUnlockScript(signature, pubKey) {
    const sigLen = signature.length;
    const pubLen = pubKey.length;
    
    // Max length for single push in this subset is 75 bytes (0x4b)
    if (sigLen > 75 || pubLen > 75) throw new Error("Push data too large for subset");

    const script = new Uint8Array(1 + sigLen + 1 + pubLen);
    script[0] = sigLen; // Push length
    script.set(signature, 1);
    script[1 + sigLen] = pubLen; // Push length
    script.set(pubKey, 2 + sigLen);
    
    return script;
}

/**
 * Builds an OP_RETURN Script for embedding arbitrary data (Max 80 bytes)
 * Format: OP_RETURN <data_length> <data>
 * 
 * @param {Uint8Array} dataBytes 
 * @returns {Uint8Array}
 */
function createOPReturnScript(dataBytes) {
    if (dataBytes.length > 80) throw new Error("OP_RETURN payload exceeds 80 bytes");
    const script = new Uint8Array(2 + dataBytes.length);
    script[0] = OP.RETURN;
    script[1] = dataBytes.length;
    script.set(dataBytes, 2);
    return script;
}

/**
 * Execute a transaction script. 
 * First runs the unlocking script (scriptSig), then passes the stack to the locking script (scriptPubKey).
 * 
 * @param {Uint8Array} scriptSig - Unlocking script from the input
 * @param {Uint8Array} scriptPubKey - Locking script from the referenced output
 * @param {Object} txContext - Context containing { checkSig: (sig, pubKey) => boolean }
 * @returns {boolean} True if the script evaluates successfully
 */
function executeScript(scriptSig, scriptPubKey, txContext) {
    const stack = [];

    /**
     * Internal script evaluator (স্ট্যাকের উপরে কমান্ডগুলো রান করে)
     */
    function evaluate(scriptBytes) {
        let i = 0;
        while (i < scriptBytes.length) {
            const opcode = scriptBytes[i];
            
            // Push Data Opcodes (0x01 to 0x4b means push 1 to 75 bytes)
            if (opcode >= 0x01 && opcode <= 0x4b) {
                const len = opcode;
                i++;
                if (i + len > scriptBytes.length) return false; // Buffer overrun protection
                const data = scriptBytes.slice(i, i + len);
                stack.push(data);
                i += len;
            } 
            // Standard Opcodes
            else {
                i++;
                switch (opcode) {
                    case OP.DUP:
                        if (stack.length < 1) return false;
                        stack.push(new Uint8Array(stack[stack.length - 1]));
                        break;
                        
                    case OP.HASH160:
                        if (stack.length < 1) return false;
                        const top = stack.pop();
                        stack.push(hash160(top));
                        break;
                        
                    case OP.EQUAL:
                        if (stack.length < 2) return false;
                        const v1 = stack.pop();
                        const v2 = stack.pop();
                        // Bitcoin pushes empty array for False, [1] for True
                        stack.push(bytesEqual(v1, v2) ? new Uint8Array([1]) : new Uint8Array([]));
                        break;

                    case OP.EQUALVERIFY:
                        if (stack.length < 2) return false;
                        const a = stack.pop();
                        const b = stack.pop();
                        if (!bytesEqual(a, b)) return false; // Immediate failure
                        break;

                    case OP.CHECKSIG:
                        if (stack.length < 2) return false;
                        const pubKey = stack.pop();
                        const sig = stack.pop();
                        if (txContext.checkSig(sig, pubKey)) {
                            stack.push(new Uint8Array([1]));
                        } else {
                            stack.push(new Uint8Array([])); // Signature verification failed
                        }
                        break;

                    case OP.RETURN:
                        return false; // Execution strictly fails if OP_RETURN is evaluated

                    default:
                        return false; // Reject unknown or disabled opcodes
                }
            }
        }
        return true;
    }

    // 1. Evaluate scriptSig (Unlocking)
    if (!evaluate(scriptSig)) return false;
    
    // 2. Evaluate scriptPubKey (Locking) using the same stack
    if (!evaluate(scriptPubKey)) return false;

    // 3. Final Verification: Stack must not be empty, and top element must be 'true' (non-zero)
    if (stack.length === 0) return false;
    const finalTop = stack[stack.length - 1];
    
    // If the top array has length > 0 and contains a non-zero byte, it is considered True
    return finalTop.some(byte => byte !== 0);
}

module.exports = {
    OP,
    createP2PKHLockScript,
    createP2PKHUnlockScript,
    createOPReturnScript,
    executeScript,
    bytesEqual
};
