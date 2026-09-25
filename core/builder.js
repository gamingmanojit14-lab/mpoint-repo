/**
 * MPOINT CORE - Transaction Builder & UTXO Selection
 * ZERO external dependencies.
 * 
 * এই মডিউলটি ইউজারের আনস্পেন্ট আউটপুট (UTXO) সিলেক্ট করে এবং 
 * প্রাইভেট-কী দিয়ে সম্পূর্ণ একটি ট্রানজেকশন তৈরি ও সাইন করে।
 */

const { TxIn, TxOut, Transaction, hexToBytes } = require('./tx.js');
const { createP2PKHLockScript, createP2PKHUnlockScript } = require('./script.js');
const { getPublicKey, sign, verify } = require('./secp256k1.js');
const { decodeCheck, pubKeyToAddress } = require('./address.js');

// Dust threshold (এর চেয়ে ছোট অ্যামাউন্টের ট্রানজেকশন আউটপুট নেটওয়ার্ক রিজেক্ট করে দেয়)
const DUST_THRESHOLD = 546n;

/**
 * Encode ECDSA Signature to Strict DER Format (BIP66 compliant)
 * বিটকয়েন স্ক্রিপ্টে শুধু (R, S) দিলে হয় না, একে নির্দিষ্ট DER ফরম্যাটে এনকোড করতে হয়।
 * 
 * @param {Uint8Array} rBytes - 32-byte R value
 * @param {Uint8Array} sBytes - 32-byte S value
 * @returns {Uint8Array} DER encoded signature
 */
function encodeDER(rBytes, sBytes) {
    let r = Array.from(rBytes);
    // Strip leading zeroes
    while (r[0] === 0 && r.length > 1) r.shift();
    // If MSB is 1 (>= 0x80), prepend 0x00 to mark as positive integer
    if (r[0] & 0x80) r.unshift(0x00);
    
    let s = Array.from(sBytes);
    while (s[0] === 0 && s.length > 1) s.shift();
    if (s[0] & 0x80) s.unshift(0x00);

    const der = [0x30, r.length + s.length + 4, 0x02, r.length, ...r, 0x02, s.length, ...s];
    return new Uint8Array(der);
}

/**
 * Decode DER format signature back to (R, S) for verification
 * (নোড যখন সিগনেচার ভেরিফাই করবে তখন এটি ব্যবহার হবে)
 */
function decodeDER(derBytes) {
    if (derBytes[0] !== 0x30) throw new Error("Invalid DER: Must start with 0x30");
    const rLen = derBytes[3];
    const rStart = 4;
    const sLen = derBytes[rStart + rLen + 1];
    const sStart = rStart + rLen + 2;
    
    return {
        r: new Uint8Array(derBytes.slice(rStart, rStart + rLen)),
        s: new Uint8Array(derBytes.slice(sStart, sStart + sLen))
    };
}

/**
 * Select UTXOs to cover target amount + fee (Coin Selection Algorithm)
 * 
 * @param {Array} utxos - List of available UTXOs [{ txid, vout, value, scriptPubKey }]
 * @param {BigInt} targetAmount - Amount to send in mptoshi
 * @param {BigInt} feeRate - Fee in mptoshi per byte (e.g., 1n)
 * @returns {Object} { selected, totalValue, fee }
 */
function selectUTXOs(utxos, targetAmount, feeRate = 1n) {
    // Sort descending (বড় UTXO আগে ব্যবহার করলে ইনপুটের সংখ্যা কমে যায়, ফলে ফি কম লাগে)
    const sorted = [...utxos].sort((a, b) => (b.value > a.value ? 1 : -1));
    
    const selected = [];
    let totalValue = 0n;
    let fee = 0n;
    
    for (const utxo of sorted) {
        selected.push(utxo);
        totalValue += BigInt(utxo.value);
        
        // Estimate tx size: Base(10) + Inputs(148 bytes each) + Outputs(34 bytes each * 2)
        const estimatedSize = BigInt(10 + (selected.length * 148) + (2 * 34));
        fee = estimatedSize * feeRate;
        
        if (totalValue >= targetAmount + fee) {
            return { selected, totalValue, fee };
        }
    }
    
    throw new Error(`Insufficient funds. Have ${totalValue}, need ${targetAmount + fee} (including fee)`);
}

/**
 * Build and sign a complete P2PKH transaction
 * 
 * @param {Uint8Array} privKeyBytes - Sender's private key
 * @param {Array} utxos - Sender's available UTXOs
 * @param {string} toAddressStr - Recipient's Mpoint Address
 * @param {BigInt} amountMptoshi - Amount to send
 * @param {BigInt} feeRate - Network fee rate (mptoshi/byte)
 * @returns {Transaction} Fully signed Transaction object
 */
function buildTransaction(privKeyBytes, utxos, toAddressStr, amountMptoshi, feeRate = 1n) {
    // 1. Derive our pubkey and change address
    const pubKey = getPublicKey(privKeyBytes, true);
    const changeAddressStr = pubKeyToAddress(pubKey);
    
    // 2. Decode addresses to pubKeyHashes
    const toPayload = decodeCheck(toAddressStr).payload;
    const changePayload = decodeCheck(changeAddressStr).payload;

    // 3. Create locking scripts
    const toScript = createP2PKHLockScript(toPayload);
    const changeScript = createP2PKHLockScript(changePayload);

    // 4. Select UTXOs
    const { selected, totalValue, fee } = selectUTXOs(utxos, amountMptoshi, feeRate);

    // 5. Build Outputs (TxOut)
    const outputs = [new TxOut(amountMptoshi, toScript)];
    const change = totalValue - amountMptoshi - fee;
    
    // If change is above dust threshold, send it back to ourselves (চেঞ্জ নিজে রেখে দেওয়া)
    if (change >= DUST_THRESHOLD) {
        outputs.push(new TxOut(change, changeScript));
    }

    // 6. Build Inputs (TxIn) with blank scriptSigs initially
    const inputs = selected.map(utxo => new TxIn(utxo.txid, utxo.vout));

    const tx = new Transaction(1, inputs, outputs, 0);

    // 7. Sign each input
    for (let i = 0; i < inputs.length; i++) {
        const utxo = selected[i];
        
        // Generate SIGHASH_ALL for this specific input
        const sigHash = tx.getSigHash(i, utxo.scriptPubKey);
        
        // ECDSA Sign
        const { r, s } = sign(sigHash, privKeyBytes);
        
        // Encode to DER
        const derSig = encodeDER(r, s);
        
        // Append SIGHASH_ALL flag (0x01)
        const finalSig = new Uint8Array(derSig.length + 1);
        finalSig.set(derSig, 0);
        finalSig[derSig.length] = 0x01; // SIGHASH_ALL = 1

        // Inject the unlocking script
        inputs[i].scriptSig = createP2PKHUnlockScript(finalSig, pubKey);
    }

    return tx;
}

module.exports = {
    encodeDER,
    decodeDER,
    selectUTXOs,
    buildTransaction,
    DUST_THRESHOLD
};
